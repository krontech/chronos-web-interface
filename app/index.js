"use strict"

document.querySelector('#password').addEventListener('change', evt => {
	console.log('changing', evt.target.value, sha256(evt.target.value))
	
	const passwordHash = sha256(evt.target.value)
	
	fetch('/v0/authenticate', {
		method: "POST",
		cache: "no-cache",
		credentials: "same-origin",
		headers: {"Content-Type": "application/json; charset=utf-8"},
		body: JSON.stringify(passwordHash),
	})
	.then(reply => console.info('http auth reply', reply))
})