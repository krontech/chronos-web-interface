"""A little wrapper class for a read-only QSettings."""

import json
from PyQt5.QtCore import QSettings

_restore = True #Turn to "false" to disable loading settings from file.
_settings = QSettings('Krontech', 'web interface') #in ~/.config/Krontech/back-of-camera interface.conf

#Read only.
def value(key: str, default: any) -> any:
	"""See http://doc.qt.io/qt-5/qsettings.html#value"""
	return json.loads(_settings.value(key, json.dumps(default))) if _restore else default