//lets setup our web server sample using express
const port = 3000
const express = require('express')
const bodyParser = require('body-parser');
const app = express()
app.use(bodyParser.json())

//in this sample, lets store the sessions in memory
const sessions = {};
//sample code for creating a new session id in memory
function createNewSessionID() {
	const new_session_id = Math.random()*100000000000000000;
	if (sessions[new_session_id]) {
		return createNewSessionID();
	} else {
		sessions[new_session_id] = {}
		return new_session_id;
	}
}
/****************************************/

//now lets make use of the handshak library
const HandshakeServer = require('../index.js').HandshakeServer;
const auth = new HandshakeServer();

//create an endpoint listening to the recommended authentication path
app.post('/' + auth.path, (req, res) => {
	console.log('********************************************************************')
	console.log('***HANDSHAKE:REQUESTED***')
	console.dir(req.body)
	//generate a unique session id with the client public key, store this in memory or a memory storage like redis/memcache
	//the response_pub_key is used to encrypt the service's responses moving forward
	const session_id = createNewSessionID();
	sessions[session_id].response = {}
	sessions[session_id].response.pub_key = req.body.client_pub_key;
	
	const result = auth.handleHandshakeRequest(req.body);
	//store the request_decryption private key in the session
	sessions[session_id].request = result.RSA
	console.log('Sesssion created ID:' + session_id);
	//return the client request keys and session id
	let body = result.response_body
	body.session_id = session_id
	console.log('***HANDSHAKE:RESPONDING***')
	console.dir(body)
	console.log('********************************************************************')
	console.log('')
	res.send(body) 
});

//create a test endpoint to see if data are transfered securely
app.post('/test', (req, res) => {
	console.log('***RECEIVED***')
	console.dir(req.body)
	//retrieve the private key and passphrase for the session and decryptRequest
	if (!sessions[req.body.session_id]) {
		res.send(403, 'Invalid Session');
	}
	const private_key = sessions[req.body.session_id].request.private_key;
	const passphrase = sessions[req.body.session_id].request.created_date;
	//decrypt the body with the decryptRequest function
	const req_body = auth.decryptRequest(private_key, passphrase, req.body)
	
	console.log('***DECRYPTED BODY***')
	console.dir(req_body)
	let response;
	if (req_body.action == 'hello' && req_body.passcode== 'whoami') {
		response = {secret_response: 'Hello ' + req_body.message}
	}else if (req_body.action == 'move' && req_body.passcode== 'whereami') {
		response = {secret_response: 'Welcome to ' + req_body.message}
	} else {
		response = {secret_response: 'Unknown action, should be hello or move'}
	}
	//encrypt the message before sending
	const response_pub_key = sessions[req.body.session_id].response.pub_key;
	response = auth.encryptResponse(response_pub_key, response)
	console.log('***RESPONDED***')
	console.dir(response)
	console.log('********************************************************************')
	console.log('')
	return res.send(response)
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`))