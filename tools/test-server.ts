"use strict";

//lets start with a basic session handler.
const SessionManagerBasic = require('adon-api-session').SessionManagerBasic;
const session = new SessionManagerBasic();
//lets setup our web server sample using express
const port = 3000;
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.json());

//now lets make use of the handshake library
import { HandshakeServer } from "../src/index";
const hs_server = new HandshakeServer();

//create an endpoint listening to the recommended authentication path
app.post('/auth/handshake', (req: any, res: any) => {
	try {
		console.log('################################################################################');
		console.log('***HANDSHAKE:REQUEST_ACCEPTED***');
		//generate a unique session id using a session manager
		const session_id = session.createSession({});
		console.log('Session:' +session_id);
		const result = hs_server.handleHandshakeRequest(req.headers, session_id);

		//store the next request decryption items in the session
		session.find(session_id).decrypt = result.decrypt;

		console.log('***HANDSHAKE:RESPONDING***');
		console.dir(result.body);
		res.set(result.headers);
		res.send(result.body);
	} catch (err) {
		console.error(err);
		res.send(err.message, 500);
	}
});

//create a test endpoint to see if data are transferred securely
app.post('/test', (req:any , res:any) => {
	try {
		//retrieve the private key and passphrase for the session and decryptRequest
		if (!session.find(req.headers.swhs_sess_id)) {
			res.send(403, 'Invalid Session');
		}
		const private_key = session.find(req.headers.swhs_sess_id).decrypt.next_prv;
		const passphrase = session.find(req.headers.swhs_sess_id).decrypt.created_date;
		//get the decrypted request
		const dec_req = hs_server.decryptRequest(req.headers, req.body, private_key, passphrase);

		console.log('***RECEIVED_REQUEST***');
		console.dir(dec_req);
		let response, res_body;
		if (dec_req.body.action == 'hello' && dec_req.body.passcode== 'whoami') {
			res_body = {secret_response: 'Hello ' + dec_req.body.message}
		}else if (dec_req.body.action == 'move' && dec_req.body.passcode== 'whereami') {
			res_body = {secret_response: 'Welcome to ' + dec_req.body.message}
		} else {
			res_body = {secret_response: 'Unknown action, should be hello or move'}
		}
		//encrypt the response body before sending
		response = hs_server.encryptResponse(req.headers.swhs_sess_id, res_body, dec_req.next_pub);
		//store the next request decryption items in the session
		session.find(req.headers.swhs_sess_id).decrypt = response.decrypt;

		console.log('***RESPONDED***');
		console.dir(response.body);
		console.log('********************************************************************');
		console.log('');
		res.set(response.headers);
		return res.send(response.body)
	} catch (err) {
		console.error(err);
		res.send(err.message, 500);
	}
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));