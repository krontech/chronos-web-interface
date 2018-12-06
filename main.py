import socketio
import eventlet
import eventlet.wsgi
from flask import *
import json
from json.decoder import JSONDecodeError
from hashlib import sha256
from hmac import compare_digest
from functools import wraps
import re

from PyQt5 import QtWidgets
from PyQt5.QtCore import pyqtSlot, QObject, QRunnable, QThreadPool

from debugger import *; dbg
import api_mock as api

#Adapted from https://pypi.org/project/python-socketio/

sio = socketio.Server()
app = Flask('chronos-web-interface')
qtApp = QtWidgets.QApplication(sys.argv)

#@app.before_first_request
#def initializeDBus(): 
#	dbg()

available_calls = api.control('available_calls')
available_keys = api.control('available_keys')


class NetworkPassword(QObject):
	"""Provides a safe equals(password) method which is always
		up-to-date with the API's networkPassword."""
	
	def __init__(self):
		super().__init__()
		self.hashedPassword = None
		api.observe('networkPassword', self.networkPasswordChanged) #Required for QDBusMessage types, since the non-future version emits the value verbatim instead of wrapped.
		
	@pyqtSlot(str)
	def networkPasswordChanged(self, password:str) -> None:
		print('network password updated to', password, sha256(bytes(password, 'utf-8')).digest())
		self.hashedPassword = sha256(bytes(password, 'utf-8')).digest()
	
	def equals(self, passwordHashHexString: str) -> bool:
		"""Compare the provided password against the camera's password.
		
			Performs constant-time validation of password to prevent
			timing attacks. … Not that those are our biggest issue
			right now. 😒"""
		
		if len(passwordHashHexString) != 64:
			raise ValueError('password is not a sha256 hex-encoded string')
		
		return compare_digest(
			self.hashedPassword,
			bytes.fromhex(passwordHashHexString) )

networkPassword = NetworkPassword()

def http_login_required(handler):
	@wraps(handler)
	def http_authentication_decorated_function(*args, **kwargs):
		if request.cookies.get('password') == None:
			print('no authentication provided')
			return ('', 401)
		if not networkPassword.equals(request.cookies.get('password')):
			print('unrecognised authentication provided')
			return ('', 401)
		return handler(*args, **kwargs)
	return http_authentication_decorated_function

def ws_login_required(handler):
	@wraps(handler)
	def ws_authentication_decorated_function(sid, *args, **kwargs):
		password = re.search('password=([0-9a-f]{64})', sio.environ[sid]['HTTP_COOKIE'])
		if not password:
			print('WS: no authentication provided')
			return {'ERROR':'no authentication provided'} #This is legitimately the best I can come up with for errors. :|
		elif not networkPassword.equals(password.groups(0)[0]):
			print('WS: unrecognised authentication provided')
			return {'ERROR':'unrecognised authentication provided'}
		else:
			return handler(sid, *args, **kwargs)
	return ws_authentication_decorated_function


@app.route('/')
def index():
	"""Serve the client-side application."""
	print('api TAF:', api.get(['totalAvailableFrames']))
	return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
	return send_from_directory('static', 'favicon.ico', mimetype='x-icon')

@app.route('/api/0.1.0/login', methods=['POST'])
def login():
	
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

@sio.on('connect')
def connect(sid, environ):
	print("connect", sid)


def parseJson(string, fallback=None) -> any:
	try:
		return json.loads(string)
	except JSONDecodeError as err:
		dbg()
		if fallback != None:
			return fallback
		else:
			raise err
		

#sio.emit('reply', room=sid) for update events
# Examples:
#	SH HTTP:
#		curl 'http://192.168.1.135/api/0.1.0/get' --data '["totalAvailableFrames"]' -H 'content-type: application/json; charset=utf-8'
#	JS HTTP:
#		fetch('/api/0.1.0/get', {
#		    method: "POST",
#		    cache: "no-cache",
#		    credentials: "same-origin",
#		    headers: {"Content-Type": "application/json; charset=utf-8"},
#		    body: JSON.stringify([5,6,{'msg':'hello'},7]),
#		})
#		.then(console.info)
#	Web URL:
#		http://192.168.1.135/api/0.1.0/get?[%22totalAvailableFrames%22,%20%22totalRecordedFrames%22,%20%22playbackFrame%22]
def registerRoute(call):
	@app.route(
		f"/api/0.1.0/{call['name']}",
		endpoint=call['name'],
		methods={'get':['GET'], 'set':['POST'], 'pure':['GET']}[call['action']] )
	@http_login_required
	def httpCall():
		#Load the query string as JSON values. (ie, /api/0.1/call?'test'&5 yields ["test", 5] as our function arguments.)
		dbusCallArgs = [
			parseJson(arg, fallback=None) #[DDR 2018-11-30] Pass `arg` to fallback to have args default-strings. This behaviour is left off because any json parse error would be caught only later, in the function call, which would be very confusing. I would consider reenabling this if there was no json-ish characters, like ' or [ or {, in the text to be stringified; but this itself is confusing, since depending on the characters in your string the parse behaviour changes. Especially bad when passing in user input. Best to leave as json-formatted, I think.
			for arg in request.args.keys()
		]
		
		#Then, load the post body, if any. This is concatenated to the parameters in the query string. The alternative would be to have the body replace the query string parameters, but this seems less confusing.
		if request.method == 'POST':
			if not request.is_json:
				raise ValueError('Only JSON-encoded POST requests are supported.')
			
			postedArgs = request.get_json()
			if type(postedArgs) is not list:
				postedArgs = [postedArgs]
			dbusCallArgs += postedArgs
		
		#Finally, actually perform the D-Bus call specified in the url path with the arguments compiled from the query string and the post body.
		#print('httpCall', call['name'], *dbusCallArgs, '→', api.control(call['name'], *dbusCallArgs))
		return jsonify(api.control(call['name'], *dbusCallArgs))
	
	@sio.on(call['name'])
	@ws_login_required
	def socketCall(sid, data):
		print('socketCall', call['name'], data)
		return api.control(call['name'], data)


for call in available_calls:
	registerRoute(call) #This must be passed as a function arg, all the routes use final call otherwise. I think the function provides a new context for the functions inside it, where this loop does not.


@sio.on('subscribe')
@ws_login_required
def subscribeToValueUpdates(sid, keys):
	try:
		unknownKey = next(key for key in keys if key not in available_keys)
		return {"ERROR": f"Unknown value, {unknownKey}, to subscribe to. Known values are: {keys(available_calls)}"}
	except StopIteration:
		for key in keys:
			print(f'subscribed {sid} to {key}')
			sio.enter_room(sid, key)
			sio.emit(key, api.get(key), room=sid)


class MessageWrapper(QObject):
	def __init__(self, key):
		super().__init__()
		self.key = key
		api.observe_future_only(key, self.emitSocketEvent) #Required for QDBusMessage types, since the non-future version emits the value verbatim instead of wrapped.
		
	@pyqtSlot('QDBusMessage')
	def emitSocketEvent(self, msg):
		print('emitting', self.key, msg.arguments()[0])
		sio.emit(self.key, msg.arguments()[0], room=self.key)
	
__wrappers = [] #Keep a reference to the wrapper objects around. The live reference is needed, or else the callback stops working.
for key in available_keys:
	__wrappers += [MessageWrapper(key)]


@sio.on('disconnect')
def disconnect(sid):
	print('disconnect ', sid)
	




if __name__ == '__main__':
	#Start a new thread to launch the wsgi server from.
	#Adapted from https://www.pymadethis.com/article/multithreading-pyqt-applications-with-qthreadpool/
	
	#Horrible hack, just poll for dbus events 60 times a second. Threading doesn't work. 🤷
	def checkForDBusEvents():
		QtWidgets.QApplication.processEvents()
		eventlet.spawn_after(0.016, checkForDBusEvents)
	eventlet.spawn_after(0.016, checkForDBusEvents)
	
	print('starting HTTP server')
	ioApp = socketio.Middleware(sio, app)
	eventlet.wsgi.server(eventlet.listen(('', api.get('HTTPPort'))), ioApp)
	
	#Starting the server is non-returning, so the following will never run.
	#It is provided as an example of what not to do.
	
	#Having a proper threaded event loop doesn't work, we can't emit websocket messages from any callbacks triggered by this.
	class Worker(QRunnable):
		@pyqtSlot()
		def run(self):
			print('starting HTTP server')
			# wrap Flask application with engineio's middleware and deploy as an eventlet WSGI server
			ioApp = socketio.Middleware(sio, app)
			eventlet.wsgi.server(eventlet.listen(('', api.get('HTTPPort'))), ioApp)
	
	#Start the non-reentrant http/ws server in a separate thread, so we can
	#	listen to D-Bus events too.
	threadpool = QThreadPool()
	worker = Worker()
	#threadpool.start(worker)