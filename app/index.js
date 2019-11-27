"use strict"

document.querySelector('#password').addEventListener('change', async evt => {
	
	//Use the built-in crypto.subtle library if available, or the sha256 library if not.
	//eg, "test" is "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	const sha256 = window.sha256 || (async text => 
		Array.prototype.map.call(new Uint8Array(
			await crypto.subtle.digest(
				"SHA-256", 
				new TextEncoder("utf-8").encode(text)
			)
		),
		x => ('00' + x.toString(16)).slice(-2)
	).join(''))
	
	console.log('changing', evt.target.value, await sha256(evt.target.value))
	
	fetch('/v0/authenticate', {
		method: "POST",
		cache: "no-cache",
		credentials: "same-origin",
		headers: {"Content-Type": "application/json; charset=utf-8"},
		body: JSON.stringify(await sha256(evt.target.value)),
	})
	.then(reply => console.info('http auth reply', reply))
})