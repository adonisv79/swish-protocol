//lets start with a basic session handler.
const { SessionManagerBasic } = require('adon-api-session');
const session = new SessionManagerBasic();
//lets setup our web server sample using express
const port = 3000;
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.json());

//now lets make use of the handshak library
const HandshakeServer = require('../index.js').HandshakeServer;
const auth = new HandshakeServer();

//create an endpoint listening to the recommended authentication path
app.post('/' + auth.path, (req, res) => {
	try {
		console.log('********************************************************************');
		console.log('***HANDSHAKE:REQUESTED***');
		console.log('header:');
		console.dir(req.headers);
		console.log('body:');
		console.dir(req.body);
		//generate a unique session id using a session manager
		const session_id = session.createSession({});
		const result = auth.handleHandshakeRequest(req.headers, session_id);

		//store the next request decryption items in the session
		session.find(session_id).decrypt = result.decrypt;

		console.log('***HANDSHAKE:RESPONDING***');
		console.log('header:');
		console.dir(result.headers);
		console.log('body:');
		console.dir(result.body);
		console.log('********************************************************************');
		console.log('');
		res.set(result.headers);
		res.send(result.body);
	} catch (err) {
		console.error(err);
		res.send(err.message, 500);
	}
});

//create a test endpoint to see if data are transfered securely
app.post('/test', (req, res) => {
	try {
		console.log('***RECEIVED***');
		console.log('header:');
		console.dir(req.headers);
		console.log('body:');
		console.dir(req.body);
		//retrieve the private key and passphrase for the session and decryptRequest
		if (!session.find(req.headers.swhs_sess_id)) {
			res.send(403, 'Invalid Session');
		}
		const private_key = session.find(req.headers.swhs_sess_id).decrypt.next_prv;
		const passphrase = session.find(req.headers.swhs_sess_id).decrypt.created_date;
		//get the decrypted request
		const dec_req = auth.decryptRequest(req.headers, req.body, private_key, passphrase);

		console.log('***DECRYPTED BODY***');
		console.dir(dec_req);
		let response;
		if (dec_req.body.action == 'hello' && dec_req.body.passcode== 'whoami') {
			res_body = {secret_response: 'Hello ' + dec_req.body.message}
		}else if (dec_req.body.action == 'move' && dec_req.body.passcode== 'whereami') {
			res_body = {secret_response: 'Welcome to ' + dec_req.body.message}
		} else {
			res_body = {secret_response: 'Unknown action, should be hello or move'}
		}
		//encrypt the response body before sending
		response = auth.encryptResponse(req.headers.swhs_sess_id, res_body, dec_req.next_pub);
		//store the next request decryption items in the session
		session.find(req.headers.swhs_sess_id).decrypt = response.decrypt;

		console.log('***RESPONDED***');
		console.dir(response);
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