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
		let swhs = hs_client.generateHandshake();
		console.log('********************************************************************')
		console.log('***HANDSHAKE:INITIATING***')
		console.dir(swhs)
		let result = await rp({
			headers: swhs.headers,
			method: 'POST',
			json: true,
			uri: hs_client.uri_auth,
			body: swhs.body,
			resolveWithFullResponse: true
		})
		console.log('***HANDSHAKE:RECEIVED***')
		console.dir(result.body)
		const handshake_pairing = {
			SWHS_SESS_ID: result.headers.swhs_sess_id,
			SWHS_ALGORITHM: result.headers.swhs_algorithm,
			SWHS_KEY: result.headers.swhs_key,
			SWHS_IV: result.headers.swhs_iv,
			is_json: result.body.is_json,
			enc_body: result.body.enc_body
		}
		var data = hs_client.handleHandshakeResponse(handshake_pairing)
		console.log('***HANDSHAKE:PAIRED***')
		console.dir(data.request)
		console.log('********************************************************************')
		console.log('')
		
		//now lets start communicating to the secured endpoints
		swhs = hs_client.encryptRequest({
			message: "Adonis Villamor",
			passcode: 'whoami',
			action: 'hello'
		})
		console.log('***SENDING***')
		console.dir(swhs)
		result = await rp({ 
			headers: swhs.headers, 
			method: 'POST', 
			json: true, 
			uri: hs_client.uri + 'test', 
			body: swhs.body,
			resolveWithFullResponse: true
			})
		console.log('***RECEIVED***')
		console.dir(result.headers)
		console.dir(result.body)
		result = hs_client.decryptResponse({
			SWHS_ALGORITHM: result.headers.swhs_algorithm,
			SWHS_KEY: result.headers.swhs_key,
			SWHS_IV: result.headers.swhs_iv,
			is_json: result.body.is_json,
			enc_body: result.body.enc_body
		})
		console.log('***DECRYPTED***')
		console.dir(result);
		console.log('********************************************************************')
		console.log('')
		
		//send a different one this time
		swhs = hs_client.encryptRequest({
			message: "Japan",
			passcode: 'whereami',
			action: 'move'
		})
		console.log('***SENDING***')
		console.dir(swhs)
		result = await rp({ 
			headers: swhs.headers, 
			method: 'POST', 
			json: true, 
			uri: hs_client.uri + 'test', 
			body: swhs.body,
			resolveWithFullResponse: true
			})
		console.log('***RECEIVED***')
		console.dir(result.headers)
		console.dir(result.body)
		result = hs_client.decryptResponse({
			SWHS_ALGORITHM: result.headers.swhs_algorithm,
			SWHS_KEY: result.headers.swhs_key,
			SWHS_IV: result.headers.swhs_iv,
			is_json: result.body.is_json,
			enc_body: result.body.enc_body
		})
		console.log('***DECRYPTED***')
		console.dir(result);
		console.log('********************************************************************')
		console.log('')
	} catch (err) {
		console.error('failed');
	}
}

test();