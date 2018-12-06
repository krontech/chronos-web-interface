"use strict"

const socket = io();

socket.on('connect', () => {
	socket.emit('subscribe', ['playbackFrame'], reply =>
		console.info('subscription reply', reply) )
})

socket.emit('get', ['totalAvailableFrames'], reply => {
	if(!reply) { return console.error('get totalAvailableFrames failed') }
	document.querySelector('#totalAvailableFrames').textContent =
		reply.totalAvailableFrames
})

socket.emit('get', ['playbackFrame'], reply => {
	if(!reply) { return console.error('get playbackFrame failed') }
	document.querySelector('#initialPlaybackFrame').textContent = reply.playbackFrame
})


socket.on('playbackFrame', playbackFrame => {
	document.querySelector('#currentPlaybackFrame').textContent = playbackFrame
})

socket.on('ping', () => console.log('ping'))
socket.on('message', data => console.log('message', data))


document.querySelector('#setPlaybackFrameHTTP').addEventListener('click', () => {
	fetch('/api/0.1.0/set', {
		method: "POST",
		cache: "no-cache",
		credentials: "same-origin",
		headers: {"Content-Type": "application/json; charset=utf-8"},
		body: JSON.stringify([{playbackFrame: 5000}]),
	})
	.then(reply => console.info('http reply', reply))
})

document.querySelector('#setPlaybackFrameWS').addEventListener('click', () =>
	socket.emit('set', {playbackFrame: 10000}, function(reply) {
		console.info('ws reply', reply)
	}) )