import socketio
import eventlet
import eventlet.wsgi
from flask import *
from json import loads as jsonLoads
from json.decoder import JSONDecodeError

from debugger import *; dbg
import api_mock as api

sio = socketio.Server()
app = Flask('chronos-web-interface')

#@app.before_first_request
#def initializeDBus():
#	dbg()


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
def registerRoute(call):
	@app.route(
		f"/api/0.1.0/{call['name']}",
		endpoint=call['name'],
		methods={
			'get': ['GET'],
			'set': ['POST'], #No getting setter functions.
			'pure': ['GET'],
		}[call['action']] )
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
		print('socketCall', call, data)
		return api.control(call, data)

for call in api.control('available_calls'):
	registerRoute(call) #This must be passed as a function arg, all the routes use final call otherwise. I think the function provides a new context for the functions inside it, where this loop does not.
	

@sio.on('disconnect')
def disconnect(sid):
	print('disconnect ', sid)

if __name__ == '__main__':
	# wrap Flask application with engineio's middleware
	app = socketio.Middleware(sio, app)

	# deploy as an eventlet WSGI server
	eventlet.wsgi.server(eventlet.listen(('', 80)), app)