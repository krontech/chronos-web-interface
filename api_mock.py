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
	Unlike the api_mock in chronos-gui-2, this one is *not* self-hosting. It
	needs to connect to something, such as the API chronos-gui-2 self-hosts.
"""

import sys
from debugger import *; dbg

from PyQt5.QtCore import pyqtSlot, QObject
from PyQt5.QtDBus import QDBusConnection, QDBusInterface, QDBusReply
from typing import Callable, Any



#####################################
#    Mock D-Bus Interface Client    #
#####################################



cameraControlAPI = QDBusInterface(
	'com.krontech.chronos.control.mock', #Service
	'/com/krontech/chronos/control/mock', #Path
	'', #Interface
	QDBusConnection.systemBus() )
cameraVideoAPI = QDBusInterface(
	'com.krontech.chronos.video.mock', #Service
	'/com/krontech/chronos/video/mock', #Path
	'', #Interface
	QDBusConnection.systemBus() )

cameraControlAPI.setTimeout(1000) #Default is -1, which means 25000ms. 25 seconds is too long to go without some sort of feedback. In worst-case, when someone's using the GUI (say a slider) and pegging the CPU, the response can take a little while. (290.8372ms max so far)
cameraVideoAPI.setTimeout(1000)

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
		
		Accepts str or [str].
		
		Returns value or [value], relatively.
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

# Keep observe()'s state up-to-date.
# TODO DDR 2018-06-22: This is broken currently, as connect() never returns here.
# We're going to ignore the fact that this doesn't work for now, as it will only matter if we reinitialize something in the camApp from this cache. 😒
__wrappers = [] #Keep a reference to the wrapper objects around. Might be needed so they don't get GC'd.
for key in _camState.keys():
	class Wrapper(QObject):
		def __init__(self):
			super(Wrapper, self).__init__()
			
			QDBusConnection.systemBus().connect('com.krontech.chronos.control.mock', '/', '',
				key, self.updateKey)
		
		@pyqtSlot('QDBusMessage')
		def updateKey(self, msg):
			_camState[key] = msg.arguments()[0]
			
	__wrappers += [Wrapper()]


class CallbackNotSilenced(Exception):
	"""Raised when the API is passed an unsilenced callback for an event.
	
		It's important to silence events (with `@silenceCallbacks`) on Qt elements
		because they'll update the API with their changes otherwise. If more than
		one value is being processed by the API at the same time, it can cause an
		infinite loop where each value changes the element and the element emits
		another change event.
		
		This is explicitly checked because having an unsilenced element emit an
		update will usually work. The update will (asychronously) wind its way
		through the system, and when it gets back to updating the emitting element
		the element will have the same value and will not emit another update.
		However, if the element has a different value, then it will change back.
		The update for the change will be in flight by this time, and the two will
		enter an infinite loop of updating the element as they fight. Any further
		changes made to the element will now emit more update events which will
		themselves loop. Since this is very hard to detect reliably in testing,
		we force at least the consideration of silencing elements on the callback,
		since it makes it much easier to track down an issue by reading the
		callback and making sure it silences the elements it changes. We can't
		reasonably test if it silences the right elements unfortunately. This
		could be solved by not emitting events to the client which initiated them,
		but while fairly trivial with the socket.io websocket library, it seems
		very difficult or impossible with d-bus.
		
		Note: It is helpful to have events propagate back to the python UI
		however. It means we can ignore updating other elements when changing
		one element, since - as either element could be updated at any time
		from (say) a web ui, it doesn't really matter where the update originates
		from. All that matters is that it does update.
	"""


def observe(name: str, callback: Callable[[Any], None], saftyCheckForSilencedWidgets=True) -> None:
	"""Observe changes in a state value.
	
		Args:
			name: ID of the state variable. "exposure", "focusPeakingColor", etc.
			callback: Function called when the state updates and upon subscription.
				Called with one parameter, the new value. Called when registered
				and when the value updates.
			isNonUpdatingCallback=False: Indicates no API requests will be made from
				this function. This is usually false, because most callbacks *do*
				cause updates to the API, and it's really hard to detect this. A
				silenced callback does not update anything, since it should silence
				all the affected fields via the @silenceCallbacks(…) decorator.
		
		Note: Some frequently updated values (> 10/sec) are only available via
			polling due to flooding concerns. They can not be observed, as they're
			assumed to *always* be changed. See the API docs for more details.
		
		
		Rationale:
		It is convenient and less error-prone if we only have one callback that
		handles the initialization and update of values. The API provides separate
		initialization and update methods, so we'll store the initialization and
		use it to perform the initial call to the observe() callback.
		
		In addition, this means we only have to query the initial state once,
		retrieving a blob of all the data available, rather than retrieving each
		key one syscall at a time as we instantiate each Qt control.
	"""
	
	if not hasattr(callback, '_isSilencedCallback') and saftyCheckForSilencedWidgets:
		raise CallbackNotSilenced(f"{callback} must consider silencing. Decorate with @silenceCallbacks(callback_name, …).")
	
	callback(_camState[name])
	QDBusConnection.systemBus().connect('com.krontech.chronos.control.mock', '/com/krontech/chronos/control/mock', '',
		name, callback)


def observe_future_only(name: str, callback: Callable[[Any], None], saftyCheckForSilencedWidgets=True) -> None:
	"""Like `observe`, but without the initial callback when observing.
	
		Useful when `observe`ing a derived value, which observe can't deal with yet.
	"""
	
	if not hasattr(callback, '_isSilencedCallback') and saftyCheckForSilencedWidgets:
		raise CallbackNotSilenced(f"{callback} must consider silencing. Decorate with @silenceCallbacks(callback_name, …).")
	
	QDBusConnection.systemBus().connect('com.krontech.chronos.control.mock', '/com/krontech/chronos/control/mock', '',
		name, callback)



def silenceCallbacks(*elements):
	"""Silence events for the duration of a callback.
	
		This allows an API element to be updated without triggering the API again.
		If the API was triggered, it might update the element which would cause an
		infinite loop.
	"""
	
	def silenceCallbacksOf(callback):
		def silencedCallback(self, *args, **kwargs):
			for element in elements:
				getattr(self, element).blockSignals(True)
			
			callback(self, *args, **kwargs)
			
			for element in elements:
				getattr(self, element).blockSignals(False)
		
		silencedCallback._isSilencedCallback = True #Checked by the API, which only takes silenced callbacks to avoid loops.
		return silencedCallback
	return silenceCallbacksOf



# Only export the functions we will use. Keep it simple. (This can be complicated later as the need arises.)
__all__ = ['control', 'video', 'observe'] #This doesn't work. Why?


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