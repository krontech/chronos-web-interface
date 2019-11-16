# -*- coding: future_fstrings -*-

"""Simple, short debugging methods and configuration.

	This module assists debugging. It configures Python to
start debugging when an error is hit, and prints out an
error in case of a segfault. It provides several functions
to print data out and enter an interactive debugger, in
addition to configuring a common logger for use in the app.

Members:
	brk: Drop into an interactive debugger. See also 
		breakIf.
	dbg: See brk.
	dump: Print and return the arg passed. Useful for
		debugging in a non-statement context, such as a
		function call. Optionally takes a string tag as the
		first arg, in addition to the dumped arg. Also
		known as "tap" or "tee".
	breakIf: Drop into an interactive debugger, but only if
		a modifier key is held on an attached keyboard.
	pp: Pretty-print a value.
	pd: Pretty-dump. Like dump but pretty-prints the value.

Example:
	from debugger import *; dbg
	dbg()
"""

import sys, pdb, pprint
from os import system, popen
from faulthandler import enable; enable() #Enable segfault backtraces, usually from C libs. (exit code 139)

from PyQt5 import QtCore

import logging; log = logging.getLogger('Chronos.gui')


# Start our interactive debugger when an error happens.
def eh(t,v,tb):
	QtCore.pyqtRemoveInputHook()
	
	#Fix system not echoing keystrokes after first auto restart.
	try:
		system('stty sane')
	except Exception as e:
		pass
	
	pdb.traceback.print_exception(t, v, tb)
	pdb.post_mortem(t=tb)
sys.excepthook = eh
del eh #Don't export.


def dbg():
	"""Start an interactive debugger at the callsite."""
	
	#Prevent pyqt5 from printing a lot of errors when we take control away from it with pdb. Unfortunately, this also means the app stops responding to things.
	QtCore.pyqtRemoveInputHook()
	
	#Fix system not echoing keystrokes after first auto restart.
	try:
		system('stty sane')
	except Exception as e:
		pass
	
	pdb.set_trace()
	# QtCore.pyqtRestoreInputHook() #Hm, can't restore input here - since we hid this frame, I think execution continues until the end of the function. Perhaps we can subclass and call setup()? Just run it manually for now.

# @pdb.hideframe #Provided by pdbpp, which also gives color and nice tab-completion.
# pdbpp segfaults Designer on my desktop computer, but works on my laptop so we'll only use it if available.
if hasattr(pdb, 'hideframe'):
	dbg = pdb.hideframe(dbg)


def dump(*args):
	"""Print and return the value. Useful for inline print-debugging.
		
		1-arity: dump(val: any)
			print val and return it.
		2-arity: dump(label, val)"""
	
	assert 1 <= len(args) <= 2, f"Incorrect number of args. Expected 1 or 2, got {len(args)}."
	log.print(': '.join([str(a) for a in args]))
	return args[0] if len(args) == 1 else args[1]


__pprinter = pprint.PrettyPrinter(
	width=int((popen('stty size').read().split()[1:2] or [80])[0]), #Width of console.
	compact=True,
)

def pp(*args, **kwargs):
	"""Pretty-print the data passed in."""
	__pprinter.pprint(*args, **kwargs)

#This doesn't really work. Running pp(dir(x)) here vs on the debug console produces different results.
def pd(*args):
	"""Pretty print and return the data passed in."""
	pp(*[dir(arg) for arg in args])

def prettyFormat(arg):
	return __pprinter.pformat(arg)