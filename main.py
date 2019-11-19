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

import asyncio
from aiohttp import web #https://docs.aiohttp.org/en/v0.17.2
import urllib
import json
from hashlib import sha256
from hmac import compare_digest
from functools import wraps
import re
import signal
import faulthandler
import sys, os

from PyQt5.QtCore import QObject, QCoreApplication, QThreadPool

from debugger import *; dbg
import api
import settings

faulthandler.enable() #Print backtraces in case of crash. (sigsegv & co)
#sio = socketio.Server(threaded=True, async_handlers=True)
qtApp = QCoreApplication(sys.argv)
threadpool = QThreadPool()

HTTPPort = 80 #TODO: Load this from env var

indexHTML = open('app/index.html', 'rb')


############################################
#   Constants, Functions, and Decorators   #
############################################


apiValueBlacklist = { #Don't expose these values via get or set, for security and safety.
}
apiFunctionBlacklist = { #Don't expose these functions via HTTP, for security and safety.
}

availableCalls = re.findall(
	"""\s*?(\w*?)\(""",
	os.popen(
		"gdbus introspect --system --dest ca.krontech.chronos.control --object-path /ca/krontech/chronos/control"
	).read()
)
availableCalls.remove('notify') #Imperfect regex, fix by using dbus introspection or adding the availableMethods call + data to the API. (We need a bit more data to select the right API method, some just get information and can be cached as a GET.)
availableKeys = api.control.callSync('availableKeys')

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
		self.serial = bytes(api.getSync('cameraSerial'), 'utf-8')
		self.hashedPassword = bytes()
		self.networkPasswordChanged()
		signal.signal(signal.SIGHUP,
			lambda signum, frame: self.networkPasswordChanged() )
		
	#@pyqtSlot(str)
	def networkPasswordChanged(self) -> None:
		try:
			self.hashedPassword = bytes(settings.value('password', 'chronos'), 'utf8')
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
	
	#@wraps(handler)
	#def wsAuthenticationDecoratedFunction(sid, *args, **kwargs):
	#	password = re.search('password=([0-9a-f]{64})', sio.environ[sid]['HTTP_COOKIE'])
	#	if not password:
	#		print('WS: no authentication provided')
	#		return {'ERROR':'no authentication provided'} #This is legitimately the best I can come up with for errors. :|
	#	elif not networkPassword.equals(password.groups(0)[0]):
	#		print('WS: unrecognised authentication provided')
	#		return {'ERROR':'unrecognised authentication provided'}
	#	else:
	#		return handler(sid, *args, **kwargs)
	
	return handler




#################################
#   HTTP and WS API Endpoints   #
#################################

def getRequestParams(request):
	if request.method not in ('GET', 'POST'):
		raise ValueError(f"Unsupported method {request.method}; use GET or POST.")
	
	params = [
		json.loads(urllib.parse.unquote(param))
		for param in request.query_string.split('&')
		if param
	]
	
	if request.method == 'POST':
		additionalParams = yield from request.post()
		if additionalParams:
			for key, value in additionalParams.items():
				params.push(
					json.loads(value) )
	
	return params


def errorResponse(message: str):
	return web.Response(
		status=500, 
		content_type='text/plain; charset=utf-8',
		body=bytes(message, 'utf8'),
	)


@asyncio.coroutine
def subscribe(request):
	response = web.StreamResponse()
	response.content_type = 'text/event-stream; charset=utf-8'
	#response.enable_compression() #Don't do this, stops events from sending.
	response.start(request)
	
	future = asyncio.Future()
	def writeResponse(key, value):
		if response._req.transport._protocol: #The connection closed error ("socket.send() raised exception.") does not propagate up to us here in this version, merely appearing on the console. It was fixed shortly after this release of aiohttp, v0.17.2. Currently, v3.6.2 is available, which does have the bug fixed among several other proper solutions.
			response.write(
				b'event: ' + bytes(key, 'utf8') + b'\n' + 
				b'data: ' + bytes(json.dumps(value), 'utf8') + b'\n' + 
				b'\n')
		else: #Not connected.
			api.apiValues.unobserve('all', writeResponse)
			future.cancel()
	api.apiValues.observe('all', writeResponse)
	return future


@asyncio.coroutine
def handle(request):
	name = request.match_info.get('name', '')
	if not name:
		return errorResponse(b"No function call specified. Try /v0/get?")
	
	try:
		params = yield from getRequestParams(request)
	except Exception as e:
		return errorResponse(f"Could not parse JSON request parameters.\n{type(e).__name__}: {e}")
	
	if name == 'webApiVersion':
		if len(params):
			return errorResponse(b"webApiVersion does not accept paramaters.")
		return web.Response(body=bytes(json.dumps([0,0,1,'']), 'utf8')) #eg, 1.3.0-rc1
	
	if name not in availableCalls:
		return errorResponse("No function exists by this name. 😕")
	
	
	response = web.StreamResponse()
	#response.content_type = 'text/json; charset=utf-8'
	##response.enable_compression()
	#response.start(request)
	##response.write(b"Hello, " + bytes(name, 'utf8'))
	
	future = asyncio.Future()
	#@asyncio.coroutine
	def writeResponse(resp):
		future.set_result(True)
		future.done()
		
		response.content_type = 'text/json; charset=utf-8'
		len(resp) > 10 and response.enable_compression() #Short requests don't have enough data to warrant compressing.
		response.start(request)
		if not response._req.transport._protocol: #The connection closed error ("socket.send() raised exception.") does not propagate up to us here in this version, merely appearing on the console. It was fixed shortly after this release of aiohttp, v0.17.2. Currently, v3.6.2 is available, which does have the bug fixed among several other proper solutions.
			return future.cancel() #Not still connected to client.
		response.write(bytes(json.dumps(resp), 'utf8'))
		#yield from response.write_eof() #This prevents the request from being returned.
	
	def writeError(err):
		future.set_result(False)
		future.done()
		
		response.content_type = 'text/plain; charset=utf-8'
		response.start(request)
		if not response._req.transport._protocol: #The connection closed error ("socket.send() raised exception.") does not propagate up to us here in this version, merely appearing on the console. It was fixed shortly after this release of aiohttp, v0.17.2. Currently, v3.6.2 is available, which does have the bug fixed among several other proper solutions.
			return future.cancel() #Not still connected to client.
		response.write(bytes(f"{type(err).__name__}: {err}", 'utf8'))
	
	if name == 'get': #Override get/set with our nicer versions.
		api.get(*params).then(writeResponse).catch(writeError)
	elif name == 'set':
		api.get(*params).then(writeResponse).catch(writeError)
	else:
		api.control.call(name, *params).then(writeResponse).catch(writeError)
	
	yield from getattr(asyncio, 'async')(future) #asyncio.async() was deprecated for ensure_future on December 6th, 2015 by Python 3.4.4. We're on the October 8th, 2014 release, 3.4.2, so this hasn't happened yet. (See https://docs.python.org/3.4/library/asyncio-task.html#asyncio.ensure_future for details.) This may throw an error when we upgrade Python because async is a keyword now, but using getattr it is at least valid Python syntax.
	return response


#request.protocol.transport.is_closing())
#response._req.transport._protocol.is_connected()
@asyncio.coroutine
def init1(loop):
	app = web.Application(loop=loop)
	
	#Call API functions and observe values.
	app.router.add_route('*', '/v0/subscribe', subscribe)
	app.router.add_route('*', '/v0/{name}', handle)
	
	#Serve the web app.
	app.router.add_route('GET', '/', lambda _:
		web.Response(status=301, headers={ 'Location':'/app' }) )
	app.router.add_route('GET', '/app', lambda _: web.Response(
		headers={ 'Content-Type':'text/html; charset=utf-8' },
		body=indexHTML.seek(0) or indexHTML.read(),
	))
	app.router.add_static('/app', 'app/', name="static app files")
	
	
	srv = yield from loop.create_server(app.make_handler(),
		'0.0.0.0', settings.value('port', 80))
	print(f"Server started on {settings.value('port', 80)}")
	return srv


@asyncio.coroutine
def init2():
	while True:
		yield QCoreApplication.processEvents()
		yield from asyncio.sleep(0.1)


#----------------



def encode(self):
	if not self.data:
		return ""
	
	lines = [
		"%s: %s" % (v, k) 
		for k, v in self.desc_map.iteritems()
		if k
	]
	
	return "%s\n\n" % "\n".join(lines)



##################
#   Self-Start   #
##################


if __name__ == '__main__':
	#Start a new thread to launch the wsgi server from.
	#Adapted from https://www.pymadethis.com/article/multithreading-pyqt-applications-with-qthreadpool/
	
	#Quit on ctrl-c.
	signal.signal(signal.SIGINT, lambda signum, frame: sys.exit(0))
	
	#Start two threads for each mainloop; flasks's app.run and qt's app.exec_().
	#class Worker(QRunnable):
	#	def run(self):
	#threadpool.start(Worker())
	#sys.exit(qtApp.exec_())
	
	getattr(asyncio, 'async')(init2())
	
	loop = asyncio.get_event_loop()
	loop.run_until_complete(init1(loop))
	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass