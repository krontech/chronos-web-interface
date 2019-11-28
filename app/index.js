(() => {
	"use strict"
	
	document.getElementById('log-out').classList.add('invisible')
	
	const generateInputs = async ()=>{
		const camera = new Camera() //from api.js
		const table = document.querySelector('#generated-input')
		const tableBody = table.querySelector('tbody')
		const template = table.querySelector('template')
		const apiKeys = await camera.call('availableKeys')
		const keyList = Object.keys(apiKeys).sort()
		const apiData = await camera.get(keyList)
		
		const updateWithData = async (target, name, data) => {
			{
				target.classList.add('pending')
				const retVal = await camera.set(name, data)
				target.classList.replace('pending', 
					retVal !== undefined ? 'updated' : 'error' )
				setTimeout(()=>target.classList.remove('updated', 'error'), 1000)
			}
		}
		
		for (const entry of keyList.map(key => ({
			name: key,
			value: apiData[key],
			meta: apiKeys[key], 
		}))) {
			const clone = document.importNode(template.content, true);
			const slots = clone.querySelectorAll('td');
			
			slots[0].textContent = entry.name
			
			let input
			switch (typeof entry.value) {
				case 'boolean':
					input = document.createElement('input')
					input.setAttribute('type', 'checkbox')
					input.checked = !!entry.value
					camera.observe(entry.name, val=>input.checked=!!val, false)
					input.addEventListener('change', async evt => updateWithData(
						evt.target, entry.name, evt.target.checked ))
					break;
				
				case 'number':
					input = document.createElement('input')
					input.setAttribute('type', 'number')
					input.setAttribute('step', 0.01)
					input.value = entry.value
					camera.observe(entry.name, val=>input.value=val, false)
					input.addEventListener('change', async evt => updateWithData(
						evt.target, entry.name, parseFloat(evt.target.value) ))
					break;
				
				case 'string':
					input = document.createElement('input')
					input.value = entry.value
					camera.observe(entry.name, val=>input.value=val, false)
					input.addEventListener('change', async evt => updateWithData(
						evt.target, entry.name, evt.target.value ))
					break;
				
				case 'object':
					input = document.createElement('textarea')
					input.value = JSON.stringify(entry.value, null, 4)
					camera.observe(entry.name, 
						(val=>input.value=JSON.stringify(val, null, 4)), false)
					input.addEventListener('change', async evt => updateWithData(
						evt.target, entry.name, JSON.parse(evt.target.value) ))
					break;
				
				default:
					throw new Error(`unknown type ${typeof entry.value} for ${entry.value}`)
			}
			
			entry.meta.set || input.setAttribute('disabled', '')
			slots[1].appendChild(input)
			
			tableBody.appendChild(clone)
		}
		
		document.getElementById('log-in').classList.add('invisible')
		document.getElementById('log-out').classList.remove('invisible')
	}
	
	generateInputs()
	
	
	
	document.querySelector('#password').addEventListener('input', async evt => {
		
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
		
		let result = await fetch('/v0/authenticate', {
			method: "POST",
			cache: "no-cache",
			credentials: "same-origin",
			headers: {"Content-Type": "application/json; charset=utf-8"},
			body: JSON.stringify(await sha256(evt.target.value)),
		})
		result = await result.json()
		
		if(result.authenticated) {
			evt.target.classList.replace('pending', 'updated')
			setTimeout(()=>evt.target.classList.remove('updated'), 1000)
			
			generateInputs()
		}
	})

	
	
	document.querySelector('#log-out').addEventListener('click', async evt => {
		evt.target.classList.add('pending')
		
		let result = await fetch('/v0/deauthenticate', {
			method: "POST",
			cache: "no-cache",
			credentials: "same-origin",
			headers: {"Content-Type": "application/json; charset=utf-8"},
		})
		result = await result.json()
		
		if(result.deauthenticated) {
			evt.target.classList.replace('pending', 'updated')
			setTimeout(()=>evt.target.classList.remove('updated'), 1000)
			
			//Remove the options since they're no longer settable. We'll repopulate them if we log in again.
			for(const tr of document.querySelectorAll('#generated-input tbody > tr')) {
				tr.parentNode.removeChild(tr)
			}
		} else {
			evt.target.classList.remove('pending')
			evt.target.classList.add('error')
			setTimeout(()=>evt.target.classList.remove('error'), 1000)
		}
		
		document.getElementById('log-in').classList.remove('invisible')
		document.getElementById('log-out').classList.add('invisible')
	})
})()