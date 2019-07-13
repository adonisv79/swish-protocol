const rp = require('request-promise');
const HandshakeClient = require('../index.js').HandshakeClient;
const SERVER_PROTOCOL = 'http';
const SERVER_IP = '127.0.0.1';
const SERVER_PORT = '3000';

const hs_client = new HandshakeClient({
	rsa_modulus_length: 512,
	handshake_ip: SERVER_IP,
	handshake_port: SERVER_PORT
});

async function test () {
	try{
		let handshake_response = await testHandShake();

		console.log('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@');
		console.log('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@');
		console.log('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@');
		if (handshake_response.status === 'ok') {
			console.log('***HANDSHAKE:PAIRED***');
			console.dir(handshake_response);
			console.log('********************************************************************');
			console.log('');
		} else {
			throw new Error('handshake failed!');
		}

		//now lets start communicating to the secured endpoints
		let result = await testRequest({
			message: "Adonis Villamor",
			passcode: 'whoami',
			action: 'hello'
		});
		console.log('***DECRYPTED***');
		console.dir(result);
		console.log('********************************************************************');
		console.log('');

		//send a different one this time
		result = await testRequest({
			message: "Japan",
			passcode: 'whereami',
			action: 'move'
		});
		console.log('***DECRYPTED***');
		console.dir(result);
		console.log('********************************************************************');
		console.log('');
	} catch (err) {
		console.error(err.message);
	}
}

async function testHandShake() {
	let swhs = hs_client.generateHandshake();
	console.log('********************************************************************');
	console.log('***HANDSHAKE:INITIATING***');
	console.dir(swhs);
	let result = await rp({
		headers: swhs.headers,
		method: 'POST',
		json: true,
		uri: hs_client.uri_auth,
		body: swhs.body,
		resolveWithFullResponse: true
	});
	console.log('***HANDSHAKE:RECEIVED***');
	console.dir(result.headers);
	console.dir(result.body);
	return hs_client.handleHandshakeResponse(result.headers, result.body);
}

async function testRequest(body) {
	swhs = hs_client.encryptRequest(body);
	console.log('***SENDING***');
	console.dir(swhs);
	result = await rp({
		headers: swhs.headers,
		method: 'POST',
		json: true,
		uri: hs_client.uri + 'test',
		body: swhs.body,
		resolveWithFullResponse: true
	});
	console.log('***RECEIVED***');
	console.dir(result.headers);
	console.dir(result.body);
	return hs_client.decryptResponse(result.headers, result.body);
}

test();