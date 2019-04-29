"use strict"

const socket = io();

socket.on('connect', () => {
	socket.emit('subscribe', ['cameraDescription'], reply =>
		console.info('subscription reply', reply) )
})

socket.emit('get', ['cameraDescription'], reply => {
	if(!reply) { return console.error('get cameraDescription failed') }
	document.querySelector('#initialCameraDescription').textContent = reply.cameraDescription
})


socket.on('cameraDescription', cameraDescription => {
	document.querySelector('#currentCameraDescription').textContent = cameraDescription
})

socket.on('message', data => console.log('message', data))


document.querySelector('#setCameraDescriptionHTTP').addEventListener('click', () => {
	fetch('/api/0.1.0/set', {
		method: "POST",
		cache: "no-cache",
		credentials: "same-origin",
		headers: {"Content-Type": "application/json; charset=utf-8"},
		body: JSON.stringify([{cameraDescription: 'test 1'}]),
	})
	.then(reply => console.info('http reply', reply))
})

document.querySelector('#setCameraDescriptionWS').addEventListener('click', () =>
	socket.emit('set', {cameraDescription: 'test 2'}, function(reply) {
		console.info('ws reply', reply)
	}) )