const rp = require('request-promise');
import { BinaryLike } from "crypto";
import { HandshakeClient } from "../index";

const SERVER_URL = 'http://localhost:3000';
const hs_client = new HandshakeClient();

async function test () {
	try{
		let handshake_response = await testHandShake();

		if (handshake_response.status === 'ok') {
			console.log('[SUCCESS]HANDSHAKE_PAIRED');
		} else {
			throw new Error('HANDSHAKE_FAILED');
		}

		//now lets start communicating to the secured endpoints
		await testRequest({
			message: "Adonis Villamor",
			passcode: 'whoami',
			action: 'hello'
		});

		//send a different one this time
		await testRequest({
			message: "Japan",
			passcode: 'whereami',
			action: 'move'
		});
	} catch (err) {
		console.error(err);
	}
}

async function testHandShake() {
	console.log('################################################################################');
	const swhs = hs_client.generateHandshake();
	console.log('***HANDSHAKE:INITIATING***');
	let response = await rp({
		headers: swhs.headers,
		method: 'POST',
		json: true,
		uri: SERVER_URL + '/auth/handshake',
		body: swhs.body,
		resolveWithFullResponse: true
	});
	console.log('***HANDSHAKE:RECEIVED***');
	const dec: any = hs_client.handleHandshakeResponse(response.headers, response.body);
	console.dir(dec);
	return dec;
}

async function testRequest(body: BinaryLike | object) {
	console.log('***SENDING***');
	console.dir(body);
	const swhs = hs_client.encryptRequest(body);
	const response = await rp({
		headers: swhs.headers,
		method: 'POST',
		json: true,
		uri: SERVER_URL + '/test',
		body: swhs.body,
		resolveWithFullResponse: true
	});
	const dec: any = hs_client.decryptResponse(response.headers, response.body);
	console.log('***RECEIVED_RESPONSE***');
	console.dir(dec);
	console.log('********************************************************************');
	console.log('');
}

test();