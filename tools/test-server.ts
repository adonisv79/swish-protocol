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
import { HandshakeServer, SwhsHeaders } from "../src/index";
const serverHS = new HandshakeServer();

function getSwhsFromReqHeaders(reqHeaders: IncomingHttpHeaders): SwhsHeaders {
	const headers: SwhsHeaders = { swhs_action: "", swhs_iv: "", swhs_key: "", swhs_next: "", swhs_sess_id: ""};
	if (typeof reqHeaders.swhs_action === "string") {
		headers.swhs_action = reqHeaders.swhs_action;
	}
	if (typeof reqHeaders.swhs_iv === "string") {
		headers.swhs_iv = reqHeaders.swhs_iv;
	}
	if (typeof reqHeaders.swhs_key === "string") {
		headers.swhs_key = reqHeaders.swhs_key;
	}
	if (typeof reqHeaders.swhs_next === "string") {
		headers.swhs_next = reqHeaders.swhs_next;
	}
	if (typeof reqHeaders.swhs_sess_id === "string") {
		headers.swhs_sess_id = reqHeaders.swhs_sess_id;
	}
	console.dir(headers);
	return headers;
}

// create an endpoint listening to the recommended authentication path
app.post("/auth/handshake", (req, res) => {
	try {
		console.log("################################################################################");
		console.log("***HANDSHAKE:REQUEST_ACCEPTED***");
		const headers = getSwhsFromReqHeaders(req.headers);
		// generate a unique session id using a session manager
		headers.swhs_sess_id = (session.createSession({}) as string);
		console.log(`Session:  ${headers.swhs_sess_id}`);
		const result = serverHS.handleHandshakeRequest(headers);

		// store the next request decryption items in the session
		session.find(headers.swhs_sess_id).decrypt = result.decrypt;

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
		if (typeof req.headers.swhs_sess_id === "string" &&
			!session.find(req.headers.swhs_sess_id)) {
			res.status(403).send("Invalid Session");
		}

		const privateKey = session.find(req.headers.swhs_sess_id).decrypt.next_prv;
		const passphrase = session.find(req.headers.swhs_sess_id).decrypt.created_date;
		// get the decrypted request
		const headers = getSwhsFromReqHeaders(req.headers);
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
		response = serverHS.encryptResponse(req.headers.swhs_sess_id as string, resBody, decReq.next_pub);
		// store the next request decryption items in the session
		session.find(req.headers.swhs_sess_id).decrypt = response.decrypt;

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
