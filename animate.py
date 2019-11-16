from typing import Callable
from PyQt5.QtCore import QTimer

def delay(parent, timeout: int, callback: Callable[[], None], *, paused: bool = False):
	"""Delay ms before calling timeout.
		
		Args:
			timeout: in ms, before calling callback
			callback: invoked after some timeout
			paused = False: don't start the timer upon creation
		
		Yield:
			The underlying QTimer object."""
	
	timer = QTimer(parent)
	timer.timeout.connect(callback)
	timer.setInterval(timeout) #ms
	timer.setSingleShot(True)
	paused or timer.start()
	return timer