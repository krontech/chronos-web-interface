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
import json
from hashlib import sha256
from hmac import compare_digest
from functools import wraps
import re
import signal
import faulthandler
import sys, os
import queue

from PyQt5.QtCore import QObject, QCoreApplication, QThreadPool, QSettings, pyqtSlot, QRunnable

from debugger import *; dbg
import api
import settings

faulthandler.enable() #Print backtraces in case of crash. (sigsegv & co)
#sio = socketio.Server(threaded=True, async_handlers=True)
qtApp = QCoreApplication(sys.argv)
threadpool = QThreadPool()

HTTPPort = 80 #TODO: Load this from env var



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


@asyncio.coroutine
def subscribe(request):
	name = request.match_info.get('name', "Anonymous")
	response = web.StreamResponse()
	response.content_type = 'text/event-stream'
	#response.enable_compression() #Don't do this, stops events from sending.
	response.start(request)
	#response.write(b"Hello, " + bytes(name, 'utf8'))
	
	future = asyncio.Future()
	def writeResponse(key, value):
		if response._req.transport._protocol: #The connection closed error ("socket.send() raised exception.") does not propagate up to us here in this version, merely appearing on the console. It was fixed shortly after this release of aiohttp, v0.17.2. Currently, v3.6.2 is available, which does have the bug fixed among several other proper solutions.
			response.write(
				b'event: '+bytes(key, 'utf8')+b'\n'+
				b'data: '+bytes(json.dumps(value), 'utf8')+b'\n'+
				b'\n')
		else: #Not connected.
			api.apiValues.unobserve('all', writeResponse)
			future.cancel()
	api.apiValues.observe('all', writeResponse)
	return future


@asyncio.coroutine
def handle(request):
	name = request.match_info.get('name', "Anonymous")
	return web.Response(body=bytes(f"Hello, {name}", 'utf8'))

#request.protocol.transport.is_closing())
#response._req.transport._protocol.is_connected()
@asyncio.coroutine
def init(loop):
	app = web.Application(loop=loop)
	app.router.add_route('GET', '/subscribe', subscribe)
	app.router.add_route('GET', '/{name}', handle)
	
	srv = yield from loop.create_server(app.make_handler(),
		'0.0.0.0', settings.value('port', 80))
	print(f"Server started on {settings.value('port', 80)}")
	return srv
	
@asyncio.coroutine
def init2():
	while True:
		yield QCoreApplication.processEvents()
		yield asyncio.sleep(0.1)


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


subscriptions = [] #[{'filter': callable(str needle), 'callback': callable()}, ...]
#@app.route("/subscribe")
def subscribe():
	keys = request.args.keys()[:]
	subscriptions.push({
		'filter': lambda needle: needle in keys,
		'callback': lambda: 0,
	})
	
	class Response(QRunnable):
		def run(self):
			app.run('0.0.0.0', port=HTTPPort)
	
	threadpool.start(Response(keys))
	
	return Response(generate(), mimetype="text/event-stream")
	
	def generate():
		print('start 2')
		q = queue.Queue()
		sseSubscriptions.append(q)
		try:
			while True:
				print('awaiting result')
				result = q.get()
				print('got result', result)
				ev = ServerSentEvent(str(result))
				yield ev.encode()
		except GeneratorExit: # Or maybe use flask signals
			print('done with sse sub')
			subscriptions.remove(q)
		print('done 2')


api.apiValues.observe('all', lambda key, value:
	print('new data', key, value) )


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
	
	asyncio.async(init2())
	
	loop = asyncio.get_event_loop()
	loop.run_until_complete(init(loop))
	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass