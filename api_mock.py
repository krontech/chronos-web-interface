# -*- coding: future_fstrings -*-

"""Mock for api.py. Allows easier development & testing of the QT interface.

	This mock is less "complete" than the C-based mock, as this mock only returns
	values sensible enough to develop the UI with. Currently the C-based mock is
	used for the camera API, and this mock is used for the control api. Note that
	this mock is still available for external programs to use via the dbus
	interface.

	Usage:
	import api_mock as api
	print(api.control('get_video_settings'))

	Remarks:
	The service provider component can be extracted if interaction with the HTTP
	api is desired. While there is a more complete C-based mock, in chronos-cli, it
	is exceptionally hard to add new calls to.
"""

import sys
from debugger import *; dbg

from PyQt5.QtCore import pyqtSlot, QObject
from PyQt5.QtDBus import QDBusConnection, QDBusInterface, QDBusReply
from typing import Callable, Any

# Set up d-bus interface. Connect to mock system buses. Check everything's working.
if not QDBusConnection.systemBus().isConnected():
	print("Error: Can not connect to D-Bus. Is D-Bus itself running?", file=sys.stderr)
	raise Exception("D-Bus Setup Error")

cameraControlAPI = QDBusInterface(
	'com.krontech.chronos.control_mock', #Service
	'/com/krontech/chronos/control_mock', #Path
	'', #Interface
	QDBusConnection.systemBus() )
cameraVideoAPI = QDBusInterface(
	'com.krontech.chronos.video_mock', #Service
	'/com/krontech/chronos/video_mock', #Path
	'', #Interface
	QDBusConnection.systemBus() )

cameraControlAPI.setTimeout(32) #Default is -1, which means 25000ms. 25 seconds is too long to go without some sort of feedback, and the only real long-running operation we have - saving - can take upwards of 5 minutes. Instead of setting the timeout to half an hour, we should probably use events which are emitted as the event progresses. One frame (at 60fps) should be plenty of time for the API to respond, and also quick enough that we'll notice any slowness. The mock replies to messages in under 1ms, so I'm not too worried here.
cameraVideoAPI.setTimeout(32) #16ms is too low.

if not cameraControlAPI.isValid():
	print("Error: Can not connect to Mock Camera Control D-Bus API at %s. (%s: %s)" % (
		cameraControlAPI.service(), 
		cameraControlAPI.lastError().name(), 
		cameraControlAPI.lastError().message(),
	), file=sys.stderr)
	raise Exception("D-Bus Setup Error")
if not cameraVideoAPI.isValid():
	print("Error: Can not connect to Mock Camera Video D-Bus API at %s. (%s: %s)" % (
		cameraVideoAPI.service(), 
		cameraVideoAPI.lastError().name(), 
		cameraVideoAPI.lastError().message(),
	), file=sys.stderr)
	raise Exception("D-Bus Setup Error")



class DBusException(Exception):
	"""Raised when something goes wrong with dbus. Message comes from dbus' msg.error().message()."""
	pass


def video(*args, **kwargs):
	"""Call the camera video DBus API. First arg is the function name.
	
		See http://doc.qt.io/qt-5/qdbusabstractinterface.html#call for details about calling.
		See https://github.com/krontech/chronos-cli/tree/master/src/api for implementation details about the API being called.
		See README.md at https://github.com/krontech/chronos-cli/tree/master/src/daemon for API documentation.
	"""
	msg = QDBusReply(cameraVideoAPI.call(*args, **kwargs))
	if not msg.isValid():
		raise DBusException("%s: %s" % (msg.error().name(), msg.error().message()))
	return msg.value()


def control(*args, **kwargs):
	"""Call the camera control DBus API. First arg is the function name.
	
		See http://doc.qt.io/qt-5/qdbusabstractinterface.html#call for details about calling.
		See https://github.com/krontech/chronos-cli/tree/master/src/api for implementation details about the API being called.
		See README.md at https://github.com/krontech/chronos-cli/tree/master/src/daemon for API documentation.
	"""
	
	msg = QDBusReply(cameraControlAPI.call(*args, **kwargs))
	if not msg.isValid():
		raise DBusException("%s: %s" % (msg.error().name(), msg.error().message()))
	return msg.value()


def get(keyOrKeys):
	"""Call the camera control DBus get method.
		
		Accepts key or [key, …], where keys are strings.
		
		Returns value or {key:value, …}, respectively.
		
		See control's `available_keys` for a list of valid inputs.
	"""
	
	keyList = [keyOrKeys] if isinstance(keyOrKeys, str) else keyOrKeys
	
	msg = QDBusReply(cameraControlAPI.call('get', keyList))
	if not msg.isValid():
		raise DBusException("%s: %s" % (msg.error().name(), msg.error().message()))
	return msg.value()[keyOrKeys] if isinstance(keyOrKeys, str) else msg.value()


def set(values):
	"""Call the camera control DBus set method. Accepts {str: value}."""
	
	msg = QDBusReply(cameraControlAPI.call('set', values))
	if not msg.isValid():
		raise DBusException("%s: %s" % (msg.error().name(), msg.error().message()))
	return msg.value()





# State cache for observe(), so it doesn't have to query the status of a variable on each subscription.
_camState = control('get', control('available_keys'))
if(not _camState):
	raise Exception("Cache failed to populate. This indicates the get call is not working.")

class APIValues(QObject):
	"""Wrapper class for subscribing to API values in the chronos API."""
	
	def __init__(self):
		super(APIValues, self).__init__()
		
		QDBusConnection.systemBus().registerObject('/com/krontech/chronos/control_mock_hack', self) #The .connect call freezes if we don't do this, or if we do this twice.
		
		self._callbacks = {}
		
		for key in _camState.keys():
			QDBusConnection.systemBus().connect('com.krontech.chronos.control_mock', '/com/krontech/chronos/control_mock', '',
				key, self.__newKeyValue)
			self._callbacks[key] = []
	
	def observe(self, key, callback):
		"""Add a function to get called when a value is updated."""
		self._callbacks[key] += [callback]
	
	def unobserve(self, key, callback):
		"""Stop a function from getting called when a value is updated."""
		raise Exception('unimplimented')
	
	@pyqtSlot('QDBusMessage')
	def __newKeyValue(self, msg):
		"""Update _camState and invoke any  registered observers."""
		_camState[msg.member()] = msg.arguments()[0]
		for callback in self._callbacks[msg.member()]:
			callback(msg.arguments()[0])
	
	def get(self, key):
		return _camState[key]

apiValues = APIValues()


def observe(name: str, callback: Callable[[Any], None], saftyCheckForSilencedWidgets=True) -> None:
	callback(apiValues.get(name))
	apiValues.observe(name, callback)


def observe_future_only(name: str, callback: Callable[[Any], None], saftyCheckForSilencedWidgets=True) -> None:
	apiValues.observe(name, callback)



#Launch the API if not imported as a library.
if __name__ == '__main__':
	from PyQt5.QtCore import QCoreApplication
	import signal
	
	app = QCoreApplication(sys.argv)
	
	#Quit on ctrl-c.
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	
	print("Self-test: Retrieve battery charge.")
	print(f"Battery charge: {get('batteryCharge')}")
	print("Self-test passed. Python API is up and running!")
	
	sys.exit(app.exec_())