"use strict"

const socket = io();
socket.emit('get', ['totalAvailableFrames'], 
	function(reply) { disp.textContent = reply.totalAvailableFrames })