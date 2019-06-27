const rp = require('request-promise');
const HandshakeClient = require('../index.js').HandshakeClient;
const SERVER_PROTOCOL = 'http'
const SERVER_IP = '127.0.0.1'
const SERVER_PORT = '3000'

const hs_client = new HandshakeClient({
	rsa_modulus_length: 512,
	handshake_ip: SERVER_IP,
	handshake_port: SERVER_PORT
});

async function test () {	
	hs_client.resetKeys(); //creates a new handshake key pairing
	try{
		let body = hs_client.handshakeBody
		console.log('********************************************************************')
		console.log('***HANDSHAKE:INITIATING***')
		console.dir(body)
		let result = await rp({
			method: 'POST',
			json: true,
			uri: hs_client.uri_auth,
			body
		})
		console.log('***HANDSHAKE:RECEIVED***')
		console.dir(result)
		var data = hs_client.handleHandshakeResponse(result)
		console.log('***HANDSHAKE:PAIRED***')
		console.dir(data)
		console.log('********************************************************************')
		console.log('')
		
		//now lets start communicating to the secured endpoints
		body = hs_client.encryptRequest({
			message: "Adonis Villamor",
			passcode: 'whoami',
			action: 'hello'
		})
		console.log('***SENDING***')
		console.dir(body)
		result = await rp({ method: 'POST', json: true, uri: hs_client.uri + 'test', body})
		console.log('***RECEIVED***')
		console.dir(result);
		result = hs_client.decryptResponse(result)
		console.log('***DECRYPTED***')
		console.dir(result);
		console.log('********************************************************************')
		console.log('')
		
		//send a different one this time
		body = hs_client.encryptRequest({
			message: "Japan",
			passcode: 'whereami',
			action: 'move'
		})
		console.log('***SENDING***')
		console.dir(body)
		result = await rp({ method: 'POST', json: true, uri: hs_client.uri + 'test', body})
		console.log('***RECEIVED***')
		console.dir(result);
		result = hs_client.decryptResponse(result)
		console.log('***DECRYPTED***')
		console.dir(result);
		console.log('********************************************************************')
		console.log('')
	} catch (err) {
		console.error(err);
	}
}

test();