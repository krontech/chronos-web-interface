#!/usr/bin/python3
# -*- coding: future_fstrings -*-

"""Web server proxying the chronos internal D-Bus API.
	
	This web server exposes the video and control APIs for the
	Chronos 1.4 High-Speed Camera, as well as a web app to make use
	of them.
	
	To enable the API and app, on your camera, navigate to the App &
	Internet screen via the Preferences & Utilities screen. Enter a
	password or click the 🎲 button to generate a secure random
	password. After this is done, you should see an App URL in the
	newly- appeared right column. This is the URL you can access the
	API as well as the web app at – `/app/*` serves the app and
	`/api/*` serves the APIs.
	
	This server is intended to be launched either via `utils/watch-
	camera`, for debugging, or simply via `python3 main.py`. It will
	need to be restarted if certain HTTP options change, such as port
	number to serve on. The server will read these configurations from
	the API on startup, but it will not restart itself if they change.
	
	As with all files in this project, this file is licenced under the
	GNU General Public Licence. See licence.txt for details/copyright.
	
Examples:
	Shell HTTP:
		curl 'http://192.168.1.135/api/0.1.0/get?\["totalAvailableFrames"\]' \
		-H 'Cookie: password=e929eb14dda6dc481466fec08eda49836c0982a939b7e44a2fc5665013c5627a'
	
	JS HTTP: (Run in a browser dev console, after logging in to the app.)
		fetch("http://192.168.1.135/api/0.1.0/set", {
			"credentials": "include", 
			"headers": { "content-type": "application/json; charset=utf-8"},
			"referrer": "http://192.168.1.135/", 
			"referrerPolicy": "no-referrer-when-downgrade", 
			"body": '[{"playbackFrame": 5000}]', 
			"method": "POST", 
			"mode": "cors"
		})
		.then(resp => resp.json())
		.then(error => console.info('set error', error)) //> set error null
		
		- or -
		
		(await fetch('/api/0.1.0/takeStillReferenceForMotionTriggering', {
				method:'post', 
				body:'[]', 
				headers: new Headers({'content-type': 'application/json'}),
			})
		).json()
	Web URL:
		http://192.168.1.135/api/0.1.0/get?[%22totalAvailableFrames%22,%20%22totalRecordedFrames%22,%20%22playbackFrame%22]
"""

import socketio
import eventlet
import eventlet.wsgi
from flask import *
import json
from hashlib import sha256
from hmac import compare_digest
from functools import wraps
import re
import signal
import faulthandler
import sys

from PyQt5.QtCore import pyqtSlot, QObject, QRunnable, QThreadPool

from debugger import *; dbg
import api

faulthandler.enable() #Print backtraces in case of crash. (sigsegv & co)
sio = socketio.Server()
app = Flask('chronos-web-interface')
qtApp = QtCore.QCoreApplication(sys.argv)

HTTPPort = 80 #TODO: Load this from env var?



############################################
#   Constants, Functions, and Decorators   #
############################################


apiValueBlacklist = { #Don't expose these values via get or set, for security and safety.
}
apiFunctionBlacklist = { #Don't expose these functions via HTTP, for security and safety.
}

#Adapted from https://pypi.org/project/python-socketio/

availableCalls = api.control('availableCalls')
availableKeys = api.control('availableKeys')

def parseJson(string, fallback=None) -> any:
	"""Parse json, optionally falling back to a value."""
	
	try:
		return json.loads(string)
	except ValueError as err:
		dbg()
		if fallback != None:
			return fallback
		else:
			raise err


def httpError(code:int, message:any):
	"""Generate a flask json error reply. Message can be a str or Exception."""
	
	if not code or not message:
		raise ValueError('jsonError(…) requires a http error code and an explanatory message.')
	
	err = jsonify({'message': str(message)})
	err.status_code = code
	return err


class NetworkPassword(QObject):
	"""Provides a safe equals(password) method which is always
		up-to-date with the API's networkPassword."""
	
	# TODO DDR 2018-12-06: Use cameraSerial to salt networkPassword.
	
	def __init__(self):
		super().__init__()
		self.serial = bytes(api.get('cameraSerial'), 'utf-8')
		self.hashedPassword = bytes()
		self.networkPasswordChanged()
		signal.signal(signal.SIGHUP,
			lambda signum, frame: self.networkPasswordChanged() )
		
	@pyqtSlot(str)
	def networkPasswordChanged(self) -> None:
		try:
			with open('/opt/camera/.network-password.hash', mode='r') as file:
				self.hashedPassword = bytes.fromhex(file.readline().strip())
			print('network password updated to', self.hashedPassword)
		except Exception as e:
			print('Could not update password:', e)
			self.hashedPassword = bytes()
	
	def equals(self, passwordHashHexString: str) -> bool:
		"""Compare the provided password against the camera's password.
		
			Performs constant-time validation of password to prevent
			timing attacks. … Not that those are our biggest issue
			right now. 😒"""
		
		if len(passwordHashHexString) != 64:
			raise ValueError('password is not a sha256 hex-encoded string')
		
		if not self.hashedPassword:
			print('authentication can not succeed without a set password')
			return False
		
		
		#password is composed of sha256(camera serial, sha256('chronos-' + password)
		#import codecs
		#print('password hash', codecs.encode(sha256(self.serial + bytes.fromhex(passwordHashHexString)).digest(), 'hex'))
		
		return compare_digest(
			self.hashedPassword,
			sha256(self.serial + bytes.fromhex(passwordHashHexString)).digest()
		)

networkPassword = NetworkPassword()


def httpLoginRequired(handler):
	"""Decorator which aborts the http request if not logged in."""
	
	@wraps(handler)
	def httpAuthenticationDecoratedFunction(*args, **kwargs):
		if request.cookies.get('password') == None:
			print('no authentication provided')
			return ('', 401)
		if not networkPassword.equals(request.cookies.get('password')):
			print('unrecognised authentication provided')
			return ('', 401)
		return handler(*args, **kwargs)
	
	return httpAuthenticationDecoratedFunction


def wsLoginRequired(handler):
	"""Decorator which aborts the websocket request if not logged in."""
	
	@wraps(handler)
	def wsAuthenticationDecoratedFunction(sid, *args, **kwargs):
		password = re.search('password=([0-9a-f]{64})', sio.environ[sid]['HTTP_COOKIE'])
		if not password:
			print('WS: no authentication provided')
			return {'ERROR':'no authentication provided'} #This is legitimately the best I can come up with for errors. :|
		elif not networkPassword.equals(password.groups(0)[0]):
			print('WS: unrecognised authentication provided')
			return {'ERROR':'unrecognised authentication provided'}
		else:
			return handler(sid, *args, **kwargs)
	
	return wsAuthenticationDecoratedFunction



#################################
#   HTTP and WS API Endpoints   #
#################################


@app.route('/')
@app.route('/app/main')
def index():
	"""Serve the home screen shell HTML.
		
		This is hydrated later through API calls, at the moment. It
		should be pre-populated, but quite frankly that's hard and we
		have minimal latency to the camera anyway.
	
		Route / as /app/main, to make it less fiddly to type in the
		app URL."""
	
	print('api TAF:', api.get('cameraMaxFrames'))
	return render_template('index.html')


@app.route('/favicon.ico')
def favicon():
	return send_from_directory('static', 'favicon.ico', mimetype='x-icon')


@app.route('/api/0.1.0/login', methods=['POST'])
def login():
	"""Set a cookie which authenicates you with the API.
		
		Accepts a json-encoded string. The string is the result of
		hex- encoding the sha-256 hashed access password plus the
		camera serial number. (See the NetworkPassword class for
		implementation details.) This hash is compared to the hash of
		the password set in the App and Internet Access screen on the
		camera. If the hashes match, a cookie is issued which
		authenticates future API calls."""
	
	callArgs = [
		parseJson(arg, fallback=None) #[DDR 2018-11-30] Pass `arg` to fallback to have args default-strings. This behaviour is left off because any json parse error would be caught only later, in the function call, which would be very confusing. I would consider reenabling this if there was no json-ish characters, like ' or [ or {, in the text to be stringified; but this itself is confusing, since depending on the characters in your string the parse behaviour changes. Especially bad when passing in user input. Best to leave as json-formatted, I think.
		for arg in request.args.keys()
	]
	
	if not request.is_json:
		raise ValueError('Only JSON-encoded POST requests are supported.')
		
	postedArgs = request.get_json()
	if type(postedArgs) is not list:
		postedArgs = [postedArgs]
	callArgs += postedArgs
	
	if len(callArgs) == 0:
		raise ValueError('No password provided to log in with.')
	if len(callArgs) > 1:
		raise ValueError('Login passed too many args, got {len(args)} when only 1 (a hex-encoded sha-256 hashed password) was expected.')
	
	if not networkPassword.equals(*callArgs):
		return (json.dumps({'authenticated':False}), 200)
	
	resp = make_response(json.dumps({'authenticated':True}))
	resp.set_cookie('password', *callArgs, httponly=True, samesite='strict') #Samesite, so it doesn't get passed around, httpOnly, because JS doesn't need access to this. Good practice, I think.
	return resp


def registerRoute(call: str, attributes: dict):
	"""Convert a HTTP call to a URL, or a WS event, into a D-Bus call.
		
		Accepts one arg, call, the name of the D-Bus method."""
	
	@app.route(
		f"/api/0.1.0/{call}",
		endpoint=call,
		methods={'get':['GET'], 'set':['POST'], 'pure':['GET']}[attributes['action']] )
	@httpLoginRequired
	def httpCall():
		#Load the query string as JSON values. (ie, /api/0.1/call?'test'&5 yields ["test", 5] as our function arguments.)
		dbusCallArgs = [
			parseJson(arg, fallback=None) #[DDR 2018-11-30] Pass `arg` to fallback to have args default-strings. This behaviour is left off because any json parse error would be caught only later, in the function call, which would be very confusing. I would consider reenabling this if there was no json-ish characters, like ' or [ or {, in the text to be stringified; but this itself is confusing, since depending on the characters in your string the parse behaviour changes. Especially bad when passing in user input. Best to leave as json-formatted, I think.
			for arg in request.args.keys()
		]
		
		#Then, load the post body, if any. This is concatenated to the parameters in the query string. The alternative would be to have the body replace the query string parameters, but this seems less confusing.
		if request.method == 'POST':
			if not request.is_json:
				return httpError(415, 'Only JSON-encoded POST requests are supported.')
			
			postedArgs = request.get_json()
			if type(postedArgs) is not list:
				return httpError(400, 'Request body must be a JSON list, the list of args to call the function with.')
			dbusCallArgs += postedArgs
		
		#Finally, actually perform the D-Bus call specified in the url path with the arguments compiled from the query string and the post body.
		#print('httpCall', call, *dbusCallArgs, '→', api.control(call, *dbusCallArgs))
		try:
			return jsonify(api.control(call, *dbusCallArgs))
		except api.APIException as e:
			return httpError(500, e)
	
	@sio.on(call)
	@wsLoginRequired
	def wsCall(sid, data):
		print('socketCall', call, data)
		
		try:
			return api.control(call, data)
		except api.APIException as e:
			sio.emit(f"{call}Error", {
				'message': str(e),
				'parameters': data, #Provide a little extra data, since ws is async we may need to track down the call that produced the error. We don't have the data available locally to the async error.
			}, room=sid)


reimplementedFunctions = {'get', 'set'} #Some functions, such as get and set, are not straight passthrough to the internal D-Bus API. (Get and Set have filtering requirements, because we don't want to let people reconfigure HTTP over HTTP and lock themselves out.)
for call, attributes in availableCalls.items():
	if call not in apiFunctionBlacklist and call not in reimplementedFunctions:
		registerRoute(call, attributes) #Call must be passed as a function arg, all the routes use final value of call otherwise. I think the function provides a new context for the functions inside it, where this loop does not.


#Get and set D-Bus calls are reimplemented below. They need some
#additional behaviour around them, since they need to filter out
#variables which control HTTP/WS API behaviour such as password and
#port number. This also allows us to put some extra checking on them.
#(Since they're going to be called quite commonly a nice error message
#will be worth it's weight in gold while debugging.)

@app.route("/api/0.1.0/get", endpoint='get', methods=['GET']) #get API values, a bit of a special case since we have a layer of access control on this one.
@httpLoginRequired
def httpApiGetProxy():
	"""HTTP to D-Bus get function. Filters blacklisted keys."""
	dbusCallArgs = [
		parseJson(arg, fallback=None) #[DDR 2018-11-30] Pass `arg` to fallback to have args default-strings. This behaviour is left off because any json parse error would be caught only later, in the function call, which would be very confusing. I would consider reenabling this if there was no json-ish characters, like ' or [ or {, in the text to be stringified; but this itself is confusing, since depending on the characters in your string the parse behaviour changes. Especially bad when passing in user input. Best to leave as json-formatted, I think.
		for arg in request.args.keys()
	]
	
	#Get takes one arg - a list of keys to retrieve.
	if len(dbusCallArgs) == 0:
		return httpError(400, 'No keys provided to retrieve values for.')
	if len(dbusCallArgs) > 1:
		return httpError(400, f'Get passed too many args, got {len(args)} when only 1 (a list of keys to get the values of) was expected.')
	if type(dbusCallArgs[0]) is not list:
		return httpError(400, f'Set takes a list of strings, keys, as its first arg. It was passed a {type(dbusCallArgs[0]).__name__} instead.')
	
	try:
		blacklistedKey = next(key for key in dbusCallArgs[0] if key in apiValueBlacklist)
		return httpError(400, f"The key {blacklistedKey} is not available through the Chronos web API. (Generally, the web interface connot configure itself for security and safety.) Sorry about that!")
	except StopIteration:
		pass #No blacklisted keys found. 🙂
	
	try:
		return jsonify(api.control('get', *dbusCallArgs))
	except api.APIException as e:
		return httpError(500, e)

@sio.on('get')
@wsLoginRequired
def wsApiGetProxy(sid, data):
	"""WS to D-Bus get function. Filters blacklisted keys."""
	print('socketCall!', 'get', data)
	
	if type(data) is not list:
		return httpError(400, f'Set takes a list of strings, keys, as its first arg. It was passed a {type(data).__name__} instead.')
	
	try:
		blacklistedKey = next(key for key in data if key in apiValueBlacklist)
		sio.emit('getError', {
			'message': f"The key {blacklistedKey} is not available through the Chronos web API. (Generally, the web interface connot configure itself for security and safety.) Sorry about that!",
			'parameters': data,
		}, room=sid)
		return
	except StopIteration:
		pass #No blacklisted keys found. 🙂
	
	try:
		return api.control('get', data)
	except api.APIException as e:
		sio.emit('getError', {
			'message': str(e),
			'parameters': data,
		}, room=sid)
		return


@app.route("/api/0.1.0/set", endpoint='set', methods=['POST']) #get API values, a bit of a special case since we have a layer of access control on this one.
@httpLoginRequired
def httpApiSetProxy():
	"""HTTP to D-Bus set function. Filters blacklisted keys."""
	dbusCallArgs = [
		parseJson(arg, fallback=None) #[DDR 2018-11-30] Pass `arg` to fallback to have args default-strings. This behaviour is left off because any json parse error would be caught only later, in the function call, which would be very confusing. I would consider reenabling this if there was no json-ish characters, like ' or [ or {, in the text to be stringified; but this itself is confusing, since depending on the characters in your string the parse behaviour changes. Especially bad when passing in user input. Best to leave as json-formatted, I think.
		for arg in request.args.keys()
	]
	
	if not request.is_json:
		return httpError(415, 'Only JSON-encoded POST requests are supported.')
	postedArgs = request.get_json()
	if type(postedArgs) is not list:
		return httpError(400, 'Request body must be a JSON list, the list of args to call the function with.')
	dbusCallArgs += postedArgs
	
	#Set takes one arg - a map of key:value pairs to set.
	if len(dbusCallArgs) == 0:
		return httpError(400, 'No keys provided to retrieve values for.')
	if len(dbusCallArgs) > 1:
		return httpError(400, f'Get passed too many args, got {len(args)} when only 1 (a list of keys to get the values of) was expected.')
	if type(dbusCallArgs[0]) is not dict:
		return httpError(400, f'Set takes {{"key": value}} pairs as its first arg. It was passed a {type(dbusCallArgs[0]).__name__} instead.')
	
	try:
		blacklistedKey = next(key for key in dbusCallArgs[0].keys() if key in apiValueBlacklist)
		return {"ERROR": f"The key {blacklistedKey} is not available through the Chronos web API. (Generally, the web interface connot configure itself for security and safety.) Sorry about that!"}
	except StopIteration:
		pass #No blacklisted keys found. 🙂
	
	try:
		return jsonify(api.control('set', *dbusCallArgs))
	except api.APIException as e:
		err = jsonify({
			'message': str(e),
			'parameters': data,
		})
		err.status_code = 500
		return err

@sio.on('set')
@wsLoginRequired
def wsApiSetProxy(sid, data):
	"""WS to D-Bus set function. Filters blacklisted keys."""
	print('socketCall!', 'set', data)
	
	if type(data) is not dict:
		raise ValueError(f'Set takes {{"key": value}} pairs as its first arg. It was passed a {type(data).__name__} instead.')
	
	try:
		blacklistedKey = next(key for key in data.keys() if key in apiValueBlacklist)
		sio.emit('setError', {
			'message': f"The key {blacklistedKey} is not available through the Chronos web API. (Generally, the web interface connot configure itself for security and safety.) Sorry about that!",
			'parameters': data,
		}, room=sid)
		return
	except StopIteration:
		pass #No blacklisted keys found. 🙂
	
	try:
		return api.control('set', data)
	except api.APIException as e:
		sio.emit('setError', {
			'message': str(e),
			'parameters': data,
		}, room=sid)


@sio.on('subscribe')
@wsLoginRequired
def subscribeToValueUpdates(sid, keys):
	"""Subscribe to value updates for keys.
	
		Args: A list of keys to listen to.
		
		Example:
			const socket = io();
			
			// Use the connect event to subscribe to updates on
			// reconnection as well as on the initial connection.
			// Events will stop otherwise if the connection is broken.
			socket.on('connect', () => {
				socket.emit('subscribe', ['playbackFrame'], error =>
					console.info('subscription error', error) )
			})
			
			// When "playbackFrame" is subscribed to, this event will
			// fire. This event event will also fire every time the
			// value is updated to something else, with the new value.
			socket.on('playbackFrame', playbackFrame => {
				console.log('playback frame is', playbackFrame)
			})"""
	try:
		unknownKey = next(key for key in keys if key not in availableKeys or key in apiValueBlacklist)
		sio.emit('subscribeToValueUpdatesError', {
			'message': f"Unknown value, {unknownKey}, to subscribe to. Known values are: {keys(availableCalls)}",
			'parameters': keys,
		}, room=sid)
		return
	except StopIteration:
		pass #No unknown keys found.
	
	for key in keys:
		print(f'subscribed {sid} to {key}')
		sio.enter_room(sid, key)
		sio.emit(key, api.get(key), room=sid)


#Turn D-Bus value-updated messages into Websocket value-updated messages.
class MessageWrapper(QObject):
	"""Hack around not being able to subscribe to D-Bus outside a QObject."""
	
	def __init__(self, key):
		super().__init__()
		self.key = key
		api.observe_future_only(key, self.emitSocketEvent) #observe_future_only is required for QDBusMessage types, since the non-future version emits the value verbatim instead of wrapped. In addition, because we don't have anything connected to us at this point to recieve events, there is no point firing them.
		
	@pyqtSlot('QDBusMessage')
	def emitSocketEvent(self, msg):
		print('emitting', self.key, msg)
		sio.emit(self.key, msg, room=self.key)
	
__wrappers = [] #Keep a reference to the wrapper objects. Without it, the callbacks stop getting called.
for key in availableKeys:
	if key not in apiValueBlacklist:
		__wrappers += [MessageWrapper(key)]



##################
#   Self-Start   #
##################


if __name__ == '__main__':
	#Start a new thread to launch the wsgi server from.
	#Adapted from https://www.pymadethis.com/article/multithreading-pyqt-applications-with-qthreadpool/
	
	#Quit on ctrl-c.
	signal.signal(signal.SIGINT, lambda signum, frame: sys.exit(0))
	
	#Horrible hack, just poll for dbus events 60 times a second. Threading doesn't work. 🤷
	def checkForDBusEvents():
		QtCore.QCoreApplication.processEvents()
		eventlet.spawn_after(0.016, checkForDBusEvents)
	eventlet.spawn_after(0.016, checkForDBusEvents)
	
	#Starting the server prints "sys:1: ReusePortUnavailableWarning: socket.SO_REUSEPORT is defined but not supported". This was fixed upstream in 2017, but for now it seems there's little we can do about it.
	eventlet.wsgi.server(
		eventlet.listen(('', HTTPPort)),
		socketio.Middleware(sio, app),
	)
	
	#Safety return. Prevents weird issues if eventlet.wsgi.server ever actually does return.
	raise Exception('eventlet unepectedly returned')
	
	#Starting the server is non-returning, so the following will never run.
	#It is provided as an example of what not to do.
	
	#Having a proper threaded event loop doesn't work, we can't emit websocket messages from any callbacks triggered by this.
	class Worker(QRunnable):
		@pyqtSlot()
		def run(self):
			print('starting HTTP server')
			# wrap Flask application with engineio's middleware and deploy as an eventlet WSGI server
			ioApp = socketio.Middleware(sio, app)
			eventlet.wsgi.server(eventlet.listen(('', HTTPPort)), ioApp)
	
	#Start the non-reentrant http/ws server in a separate thread, so we can
	#	listen to D-Bus events too.
	threadpool = QThreadPool()
	worker = Worker()
	threadpool.start(worker)