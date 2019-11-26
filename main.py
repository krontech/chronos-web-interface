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
import binascii

from PyQt5.QtCore import QObject, QCoreApplication, QThreadPool

from debugger import *; dbg
import api
import settings

faulthandler.enable() #Print backtraces in case of crash. (sigsegv & co)
#sio = socketio.Server(threaded=True, async_handlers=True)
qtApp = QCoreApplication(sys.argv)
threadpool = QThreadPool()

indexHTML = open('app/index.html', 'rb')


availableCalls = re.findall(
	"""\s*?(\w*?)\(""",
	os.popen(
		"gdbus introspect --system --dest ca.krontech.chronos.control --object-path /ca/krontech/chronos/control"
	).read()
)
availableCalls.remove('notify') #Imperfect regex, fix by using dbus introspection or adding the availableMethods call + data to the API. (We need a bit more data to select the right API method, some just get information and can be cached as a GET.)
availableKeys = api.control.callSync('availableKeys')



def hexHash(*, password: str):
	return binascii.hexlify(
		sha256(
			bytes(api.apiValues.get('cameraSerial'), 'utf-8') + 
			sha256(bytes(password, 'utf-8')).digest()
		).digest()
	).decode('utf-8')


def errorResponse(message: str):
	return web.Response(
		status=500, 
		content_type='text/plain; charset=utf-8',
		body=bytes(message, 'utf8'),
	)



def getRequestParams(request):
	if request.method not in ('GET', 'POST'):
		raise ValueError(f"Unsupported method {request.method}; use GET or POST.")
	
	params = [
		json.loads(urllib.parse.unquote(param))
		for param in request.query_string.split('&')
		if param
	]
	
	
	if request.method == 'POST':
		postData = yield from request.json()
		params += postData if type(postData) is list else [postData]
	
	return params



###############################
#   Authentication Routines   #
###############################


class NetworkPassword(QObject):
	"""Provides a safe equals(password) method which is always
		up-to-date with the API's networkPassword."""
	
	# TODO DDR 2018-12-06: Use cameraSerial to salt networkPassword.
	
	def __init__(self):
		super().__init__()
		self.serial = bytes(api.apiValues.get('cameraSerial'), 'utf-8')
		self.hashedPassword = bytes()
		self.networkPasswordChanged()
		signal.signal(signal.SIGHUP,
			lambda signum, frame: self.networkPasswordChanged() )
	
	
	def networkPasswordChanged(self) -> None:
		try:
			#Defaults to "chronos", for now. We should not do this because we don't want a default password, let alone such a bad one.
			assert len(settings.value('password', '')), "Password must be given for web server to start. (Try setting this in the App & Internet Access screen on the camera.)"
			self.hashedPassword = bytes.fromhex(
				settings.value('password')# or hexHash(password="chronos")
			)
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
			print('authentication can not succeed without a password set on the camera')
			return False
		
		
		#password is composed of sha256(camera serial, sha256('chronos-' + password)
		#import codecs
		#print('password hash', codecs.encode(sha256(self.serial + bytes.fromhex(passwordHashHexString)).digest(), 'hex'))
		
		return compare_digest(
			self.hashedPassword,
			sha256(self.serial + bytes.fromhex(passwordHashHexString)).digest()
		)
networkPassword = NetworkPassword()



@asyncio.coroutine
def authenticate(request):
	"""Set a cookie which authenticates you with the API.
		
		Accepts a json-encoded string. The string is the result of
		hex- encoding the sha-256 hashed access password plus the
		camera serial number. (See the NetworkPassword class for
		implementation details.) This hash is compared to the hash of
		the password set in the App and Internet Access screen on the
		camera. If the hashes match, a cookie is issued which
		authenticates future API calls."""
	
	try:
		params = yield from getRequestParams(request)
	except Exception as e:
		return errorResponse(f"Could not parse JSON request parameters.\n{type(e).__name__}: {e}")
	
	if len(params) == 0:
		return errorResponse(f'No password provided to log in with.')
	if len(params) > 1:
		return errorResponse(f'Login passed too many args, {len(args)}, when only a hex-encoded sha-256 hashed password was expected.')
	
	if not networkPassword.equals(*params):
		return web.Response(
			content_type='text/json; charset=utf-8',
			body=b'{"authenticated": false}',
		)
	
	
	resp = web.Response(
		content_type='text/json; charset=utf-8',
		body=b'{"authenticated": true}',
	)
	resp.set_cookie('password', *params, httponly=True) #samesite='None') not supported yet #Explicitly allow other websites to use the API too.
	return resp


@asyncio.coroutine
def deauthenticate(request):
	"""Remove the API authentication cookie set by authenticate()."""
	
	resp = web.Response(
		content_type='text/json; charset=utf-8',
		body=b'{"deauthenticated": true}',
	)
	resp.set_cookie('password', '«expired»', httponly=True, expires='Thu, 01 Jan 1970 00:00:00 GMT') #samesite='None') not supported yet #Explicitly allow other websites to use the API too.
	return resp



def authenticationRequired(handler):
	"""Decorator which aborts the http request if not logged in."""
	
	@wraps(handler)
	def httpAuthenticationDecoratedFunction(request):
		if request.cookies.get('password') == None:
			return web.Response(
				status = 401, 
				content_type = 'text/plain; charset=utf-8',
				body = b'no authentication provided',
			)
		try:
			if not networkPassword.equals(request.cookies.get('password')):
				return web.Response(
					status = 401, 
					content_type = 'text/plain; charset=utf-8',
					body = b'unrecognised authentication provided',
				)
		except ValueError as err:
			return web.Response(
				status = 401, 
				content_type = 'text/plain; charset=utf-8',
				body = bytes(str(err), 'utf8'),
			)
		
		return handler(request)
	
	return httpAuthenticationDecoratedFunction



###################
#   API Proxies   #
###################


@asyncio.coroutine
@authenticationRequired
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
@authenticationRequired
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
		api.set(*params).then(writeResponse).catch(writeError)
	else:
		api.control.call(name, *params).then(writeResponse).catch(writeError)
	
	yield from getattr(asyncio, 'async')(future) #asyncio.async() was deprecated for ensure_future on December 6th, 2015 by Python 3.4.4. We're on the October 8th, 2014 release, 3.4.2, so this hasn't happened yet. (See https://docs.python.org/3.4/library/asyncio-task.html#asyncio.ensure_future for details.) This may throw an error when we upgrade Python because async is a keyword now, but using getattr it is at least valid Python syntax.
	return response



######################
#   Initialization   #
######################


#request.protocol.transport.is_closing())
#response._req.transport._protocol.is_connected()
@asyncio.coroutine
def init1(loop):
	"""Start processing web events."""
	app = web.Application(loop=loop)
	
	#Call API functions and observe values.
	app.router.add_route('POST', '/v0/authenticate',   authenticate)
	app.router.add_route('POST', '/v0/deauthenticate', deauthenticate)
	app.router.add_route('*',    '/v0/subscribe',      subscribe)
	app.router.add_route('*',    '/v0/{name}',         handle)
	
	#Serve the web app.
	app.router.add_route('GET', '/', lambda _:
		web.Response(status=301, headers={ 'Location':'/app' }) )
	app.router.add_route('GET', '/app', lambda _: web.Response(
		headers={ 'Content-Type':'text/html; charset=utf-8' },
		body=indexHTML.seek(0) or indexHTML.read(),
	))
	app.router.add_static('/app', 'app/', name="static app files")
	
	
	print(f"Server running on port {settings.value('port', 80)}.")
	srv = yield from loop.create_server(
		app.make_handler(),
		'0.0.0.0',
		settings.value('port', 80),
	)
	return srv



@asyncio.coroutine
def init2():
	"""Start processing d-bus events."""
	while True:
		yield QCoreApplication.processEvents()
		yield from asyncio.sleep(1/30) #of one second



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