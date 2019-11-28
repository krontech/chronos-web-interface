"use strict"

class Camera extends EventSource {
	constructor() {
		super("/v0/subscribe")
		
		this.addEventListener("open", evt => {
			console.info('SSE OPEN', evt)
		})
		this.addEventListener("error", evt => {
			console.info('SSE ERR', evt)
		})
		this.addEventListener("state", evt => {
			console.info('SSE3', evt.data)
		})
	}
	
	async observe(property, callback, initialise=true) {
		if (initialise) {
			const initialValue = await fetch(`/v0/get?["${property}"]`, {
				method: "GET",
				cache: "no-cache",
				credentials: "same-origin",
				headers: {"Content-Type": "application/json; charset=utf-8"},
			})
			
			callback(await initialValue.json())
		}
		
		this.addEventListener(property, event => {
			callback(JSON.parse(event.data))
		})
	}
	
	async get(propertyOrProperties) {
		const url = `/v0/get?${encodeURIComponent(JSON.stringify(propertyOrProperties))}`
		return await (await fetch(url, {
			method: "GET",
			cache: "no-cache",
			credentials: "same-origin",
			headers: {"Content-Type": "application/json; charset=utf-8"},
		})).json()
	}
	
	async set(...args) {
		return await (await fetch('/v0/set', {
			method: "POST",
			cache: "no-cache",
			credentials: "same-origin",
			headers: {"Content-Type": "application/json; charset=utf-8"},
			body: JSON.stringify(args.length == 1 ? args[0] : args),
		})).json()
	}
	
	async call(call, ...args) {
		return await (await fetch(`/v0/${call}`, {
			method: "POST",
			cache: "no-cache",
			credentials: "same-origin",
			headers: {"Content-Type": "application/json; charset=utf-8"},
			body: JSON.stringify(args),
		})).json()
	}
}