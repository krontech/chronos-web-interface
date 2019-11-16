# -*- coding: future_fstrings -*-

"""Little wrapper class for QSettings which implements subscriptions.

Observe a key with a callback, called when the key is changed or initialized.
"""

from collections import defaultdict
from typing import Callable, Optional
import json

from PyQt5.QtCore import QSettings

_restore = True #Turn to "false" to disable loading settings from file.
_settings = QSettings('Krontech', 'web interface') #in ~/.config/Krontech/back-of-camera interface.conf
_callbacks = defaultdict(list)

#Read only.
def value(key: str, default: any) -> any:
	"""See http://doc.qt.io/qt-5/qsettings.html#value"""
	return json.loads(_settings.value(key, json.dumps(default))) if _restore else default