
import { BinaryLike } from "crypto";

import {
	HybridCryptography,
	SwishBody,
	SwishHeaders } from "./HybridCryptography";

export interface SwishDecryption {
	next_prv: string;
	created_date: number;
}

export class HandshakeServer extends HybridCryptography {

	constructor() {
		super();
	}

	/**
	 * Handles a handshake request from a new client
	 * @param headers - the request headers
	 * @param sessionId - the unique session identifier
	 */
	public handleHandshakeRequest(headers: SwishHeaders) {
		if (headers.swish_sess_id === "") {
			throw new Error("SESSION_ID_INVALID");
		} else if (headers.swish_action !== "handshake_init") {
			throw new Error("HANDSHAKE_INVALID_INIT");
		} else if (headers.swish_iv.length < 10) {
			throw new Error("HANDSHAKE_AES_IV_INVALID");
		}

		// first lets decrypt that public key for sending our responses to this client
		const responsePubKey = this.aesDecrypt(
			headers.swish_next, false,
			headers.swish_key, headers.swish_iv);

		// encrypt an ok response using the client's response public key
		const result = this.encryptResponse(headers.swish_sess_id, { status: "ok" }, responsePubKey);

		result.headers.swish_action = "handshake_response"; // override the action value
		return result;
	}

	/**
	 * Decrypt the encrypted request with the session's next request decrypt key
	 * @param headers - the request headers
	 * @param req_body - the request body
	 * @param next_prv - the RSA private key used to decrypt the req_body
	 * @param passphrase - the Passphrase used to generate the RSA private key
	 */
	public decryptRequest(
		headers: SwishHeaders,
		body: SwishBody,
		nextPrv: Buffer,
		passphrase: string) {

		const decrypted = this.hybridDecrypt(
			body,
			headers.swish_next,
			nextPrv,
			passphrase,
			headers.swish_key,
			headers.swish_iv);

		return {
			body: decrypted.data as any,
			next_pub: decrypted.nextPub,
		};
	}

	/**
	 * Encrypt the response with the session public key
	 * @param swishSessionId - the unique session identifier
	 * @param body - the response body to encrypt
	 */
	public encryptResponse(
		swishSessionId: string,
		body: BinaryLike | object,
		rsaPub: Buffer | string,
		): { headers: SwishHeaders; body: SwishBody; decrypt: SwishDecryption} {
		if (!rsaPub) {
			throw new Error("PUBLIC_KEY_INVALID");
		} else if (!body) {
			throw new Error("BODY_INVALID");
		}

		// use Hybrid Encryption and return the response in the proper structure
		const result = this.hybridEncrypt(body, rsaPub);
		return {
			body: {
				enc_body: result.encData,
				is_json: result.isJson,
			},
			decrypt: {
				created_date: result.created_date,
				next_prv: result.next_prv,
			},
			headers: {
				swish_action: "encrypt_response",
				swish_iv: result.iv,
				swish_key: result.key,
				swish_next: result.nextPub,
				swish_sess_id: swishSessionId,
			},
		};
	}
}
