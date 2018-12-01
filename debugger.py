"""Simple, short debugging methods.

Both the provided dbg() and brk() calls are the same, calling up an interactive
command line.

Example:
	from debugger import *; dbg
	dbg()
"""

import sys, pdb


# Start our interactive debugger when an error happens.
sys.excepthook = lambda t, v, tb: (
	pdb.traceback.print_exception(t, v, tb),
	pdb.post_mortem(t=tb)
)

@pdb.hideframe
def brk():
	"""Start an interactive debugger at the callsite."""
	pdb.set_trace()

dbg = brk #I keep using one or the other. Either should probably work, let's make debugging easy on ourselves.


def dump(val, label=None):
	"""Print and return the value. Useful for inline print-debugging."""
	print(label, val) if label else print(val)
	return val