import socketio
import eventlet
import eventlet.wsgi
from flask import *
from json import loads as jsonLoads
from json.decoder import JSONDecodeError

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


@app.route('/')
def index():
	"""Serve the client-side application."""
	print('api TAF:', api.get(['totalAvailableFrames']))
	return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
	return send_from_directory('static', 'favicon.ico', mimetype='x-icon')

@sio.on('connect')
def connect(sid, environ):
	print("connect ", sid)


def parseJson(string, fallback=None) -> any:
	try:
		return jsonLoads(string)
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
	def httpCall():
		#Load the query string as JSON values. (ie, /api/0.1/call?'test'&5 yields ["test", 5] as our function arguments.)
		dbusCallArgs = [
			parseJson(arg, fallback=None) #[DDR 2018-11-30] Pass `arg` to fallback to have args default-strings. This behaviour is left off because any json parse error would be caught only later, in the function call, which would be very confusing. I would consider reenabling this if there was no json-ish characters, like ' or [ or {, in the text to be stringified; but this itself is confusing, since depending on the characters in your string the parse behaviour changes. Especially bad when passing in user input. Best to leave as json-formatted, I think.
			for arg in request.args.keys()
		]
		
		#Then, load the post body, if any. This is concatenated to the parameters in the query string. The alternative would be to have the body replace the query string parameters, but this seems less confusing.
		if request.method == 'POST':
			if not request.is_json:
				raise ValueError('Only JSON POST requests are supported.')
			
			postedArgs = request.get_json()
			if type(postedArgs) is not list:
				postedArgs = [postedArgs]
			dbusCallArgs += postedArgs
		
		#Finally, actually perform the D-Bus call specified in the url path with the arguments compiled from the query string and the post body.
		#print('httpCall', call['name'], *dbusCallArgs, '→', api.control(call['name'], *dbusCallArgs))
		return jsonify(api.control(call['name'], *dbusCallArgs))
	
	@sio.on(call['name'])
	def socketCall(sid, data):
		print('socketCall', call['name'], data)
		return api.control(call['name'], data)


for call in available_calls:
	registerRoute(call) #This must be passed as a function arg, all the routes use final call otherwise. I think the function provides a new context for the functions inside it, where this loop does not.


@sio.on('subscribe')
def subscribeToValueUpdates(sid, keys):
	try:
		unknownKey = next(key for key in keys if key not in available_keys)
		return {"ERROR": f"Unknown value, {unknownKey}, to subscribe to. Known values are: {keys(available_calls)}"}
	except StopIteration:
		for key in keys:
			print(f'subscribed {sid} to {key}')
			sio.enter_room(sid, key)
			sio.emit(key, api.get(key), room=sid)


class Wrapper(QObject):
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
	__wrappers += [Wrapper(key)]


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
	eventlet.wsgi.server(eventlet.listen(('', 80)), ioApp)
	
	#Having a proper threaded event loop doesn't work, we can't emit websocket messages from any callbacks triggered by this.
	class Worker(QRunnable):
		@pyqtSlot()
		def run(self):
			print('starting HTTP server')
			# wrap Flask application with engineio's middleware and deploy as an eventlet WSGI server
			ioApp = socketio.Middleware(sio, app)
			eventlet.wsgi.server(eventlet.listen(('', 80)), ioApp)
	
	#Start the non-reentrant http/ws server in a separate thread, so we can
	#	listen to D-Bus events too.
	#threadpool = QThreadPool()
	#worker = Worker()
	#threadpool.start(worker)