
import { BinaryLike } from "crypto";

import {
	HybridCryptography,
	SwhsBody,
	SwhsHeaders } from "./HybridCryptography";

export interface SwhsDecryption {
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
	public handleHandshakeRequest(headers: SwhsHeaders) {
		if (headers.swhs_sess_id === "") {
			throw new Error("SESSION_ID_INVALID");
		} else if (headers.swhs_action !== "handshake_init") {
			throw new Error("HANDSHAKE_INVALID_INIT");
		} else if (headers.swhs_iv.length < 10) {
			throw new Error("HANDSHAKE_AES_IV_INVALID");
		}

		// first lets decrypt that public key for sending our responses to this client
		const responsePubKey = this.aesDecrypt(
			headers.swhs_next, false,
			headers.swhs_key, headers.swhs_iv);

		// encrypt an ok response using the client's response public key
		const result = this.encryptResponse(headers.swhs_sess_id, { status: "ok" }, responsePubKey);

		result.headers.swhs_action = "handshake_response"; // override the action value
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
		headers: SwhsHeaders,
		body: SwhsBody,
		nextPrv: Buffer,
		passphrase: string) {

		const decrypted = this.hybridDecrypt(
			body,
			headers.swhs_next,
			nextPrv,
			passphrase,
			headers.swhs_key,
			headers.swhs_iv);

		return {
			body: decrypted.data as any,
			next_pub: decrypted.nextPub,
		};
	}

	/**
	 * Encrypt the response with the session public key
	 * @param swhsSessionId - the unique session identifier
	 * @param body - the response body to encrypt
	 */
	public encryptResponse(
		swhsSessionId: string,
		body: BinaryLike | object,
		rsaPub: Buffer | string,
		): { headers: SwhsHeaders; body: SwhsBody; decrypt: SwhsDecryption} {
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
				swhs_action: "encrypt_response",
				swhs_iv: result.iv,
				swhs_key: result.key,
				swhs_next: result.nextPub,
				swhs_sess_id: swhsSessionId,
			},
		};
	}
}
