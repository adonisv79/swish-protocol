// lets start with a basic session handler.
const SessionManagerBasic = require("adon-api-session").SessionManagerBasic;
const session = new SessionManagerBasic();
// lets setup our web server sample using express
const port = 3000;
import { default as bodyParser } from "body-parser";
import { default as express } from "express";
import { IncomingHttpHeaders } from "http";
const app = express();
app.use(bodyParser.json());

// now lets make use of the handshake library
import { HandshakeServer, SwishHeaders } from "../src/index";
const serverHS = new HandshakeServer();

function getSwishFromReqHeaders(reqHeaders: IncomingHttpHeaders): SwishHeaders {
	const headers: SwishHeaders = { swish_action: "", swish_iv: "", swish_key: "", swish_next: "", swish_sess_id: ""};
	if (typeof reqHeaders.swish_action === "string") {
		headers.swish_action = reqHeaders.swish_action;
	}
	if (typeof reqHeaders.swish_iv === "string") {
		headers.swish_iv = reqHeaders.swish_iv;
	}
	if (typeof reqHeaders.swish_key === "string") {
		headers.swish_key = reqHeaders.swish_key;
	}
	if (typeof reqHeaders.swish_next === "string") {
		headers.swish_next = reqHeaders.swish_next;
	}
	if (typeof reqHeaders.swish_sess_id === "string") {
		headers.swish_sess_id = reqHeaders.swish_sess_id;
	}
	console.dir(headers);
	return headers;
}

// create an endpoint listening to the recommended authentication path
app.post("/auth/handshake", (req, res) => {
	try {
		console.log("################################################################################");
		console.log("***HANDSHAKE:REQUEST_ACCEPTED***");
		const headers = getSwishFromReqHeaders(req.headers);
		// generate a unique session id using a session manager
		headers.swish_sess_id = (session.createSession({}) as string);
		console.log(`Session:  ${headers.swish_sess_id}`);
		const result = serverHS.handleHandshakeRequest(headers);

		// store the next request decryption items in the session
		session.find(headers.swish_sess_id).decrypt = result.decrypt;

		console.log("***HANDSHAKE:RESPONDING***");
		console.dir(result.body);
		res.set(result.headers);
		res.send(result.body);
	} catch (err) {
		console.error(err);
		res.status(500).send((err as Error).message);
	}
});

// create a test endpoint to see if data are transferred securely
app.post("/test", (req , res) => {
	try {
		// retrieve the private key and passphrase for the session and decryptRequest
		if (typeof req.headers.swish_sess_id === "string" &&
			!session.find(req.headers.swish_sess_id)) {
			res.status(403).send("Invalid Session");
		}

		const privateKey = session.find(req.headers.swish_sess_id).decrypt.next_prv;
		const passphrase = session.find(req.headers.swish_sess_id).decrypt.created_date;
		// get the decrypted request
		const headers = getSwishFromReqHeaders(req.headers);
		const decReq = serverHS.decryptRequest(headers, req.body, privateKey, passphrase);

		console.log("***RECEIVED_REQUEST***");
		console.dir(decReq);
		let response, resBody;
		if (decReq.body.action === "hello" && decReq.body.passcode === "whoami") {
			resBody = { secret_response: `Hello ${decReq.body.message}` };
		} else if (decReq.body.action === "move" && decReq.body.passcode === "whereami") {
			resBody = { secret_response: `Welcome to ${decReq.body.message}` };
		} else {
			resBody = { secret_response: "Unknown action, should be hello or move" };
		}
		// encrypt the response body before sending
		response = serverHS.encryptResponse(req.headers.swish_sess_id as string, resBody, decReq.next_pub);
		// store the next request decryption items in the session
		session.find(req.headers.swish_sess_id).decrypt = response.decrypt;

		console.log("***RESPONDED***");
		console.dir(response.body);
		console.log("********************************************************************");
		console.log("");
		res.set(response.headers);
		return res.send(response.body)
	} catch (err) {
		console.error(err);
		res.status(500).send((err as Error).message);
	}
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
