import { BinaryLike } from "crypto";

import { HybridCryptography, SwhsBody, SwhsHeaders } from "./HybridCryptography";

export class HandshakeClient extends HybridCryptography {
	private strSessionId!: string;
	private objKeys: {
		next_pub: Buffer | string;
		next_prv: Buffer | string;
		created_date: number;
	};

	/**
	 * Gets the current client session id
	 */
	public get SessionId(): string {
		return this.strSessionId;
	}

	constructor() {
		super();
		// set the default
		this.objKeys = { next_pub: "", next_prv: "", created_date: -1 };
		this.strSessionId = "";
	}

	/**
	 * Validates the headers with added keys expected from a server response
	 */
	public validateResponseSwhsHeader(headers: SwhsHeaders): void {
		if (!headers.swhs_sess_id) {
			throw new Error("HANDSHAKE_INVALID: Missing header swhs_sess_id");
		} else if (this.strSessionId && this.strSessionId !== headers.swhs_sess_id) {
			throw new Error("HANDSHAKE_INVALID: Session ID mismatch");
		}
	}

	/**
	 * Generates a new handshake request and retrieve the next generated SWHS header values
	 */
	public generateHandshake(): { headers: SwhsHeaders; body: SwhsBody} {
		// create a new RSA key pair
		const date = new Date();
		const rsa = this.createRSAEncrytptionKey(date.getTime().toString());
		this.strSessionId = "";
		this.objKeys = {
			created_date: date.getTime(),
			next_prv: rsa.private_key,
			next_pub: rsa.public_key,
		};

		// create a new aes set to encrypt the "response public key"
		const aesSet = this.createAESEncryptionKey();
		const encNextPub = this.aesEncrypt(
			this.objKeys.next_pub,
			aesSet.key,
			aesSet.iv);

		return {
			body: {
				is_json: false,
			},
			headers: {
				swhs_action: "handshake_init",
				swhs_iv: aesSet.iv.toString("base64"),
				swhs_key: aesSet.key.toString("base64"),
				swhs_next: encNextPub,
				swhs_sess_id: "",
			},
		};
	}

	/**
	 * Encrypts a request body and retrieve the next generated SWHS header values
	 * @param body - the request body to encrypt
	 */
	public encryptRequest(body: BinaryLike | object): { headers: SwhsHeaders; body: SwhsBody } {
		if (!body) {
			throw new Error("BODY_INVALID");
		} else if (!this.objKeys.next_pub) {
			throw new Error("Next public request key is not set!");
		}

		const result = this.hybridEncrypt(body, this.objKeys.next_pub);
		this.objKeys.next_prv = result.next_prv;
		this.objKeys.created_date = result.created_date;

		return {
			body: {
				enc_body: result.encData,
				is_json: result.isJson,
			},
			headers: {
				swhs_action: "request_basic",
				swhs_iv: result.iv,
				swhs_key: result.key,
				swhs_next: result.nextPub, // this is the next response
				swhs_sess_id: this.strSessionId,
			},
		};
	}

	/**
	 * Handle the response from the SWHS service and stores the next pub key in the chain
	 * @param headers - The response headers
	 * @param body - The response body
	 */
	public handleHandshakeResponse(headers: SwhsHeaders, body: SwhsBody) {
		console.dir(body);
		// if new session id, assign it
		if (!this.strSessionId && headers.swhs_sess_id) {
			this.strSessionId = headers.swhs_sess_id;
		}
		// retrieve the next request sequenced pub key
		return this.decryptResponse(headers, body);
	}

	/**
	 * Decrypt the encrypted response and stores the next pub key in the chain
	 * @param headers - The response headers
	 * @param body - The response body
	 */
	public decryptResponse(headers: SwhsHeaders, body: SwhsBody) {
		this.validateResponseSwhsHeader(headers);
		const decrypted = this.hybridDecrypt(
			body,
			headers.swhs_next,
			this.objKeys.next_prv,
			this.objKeys.created_date.toString(),
			headers.swhs_key,
			headers.swhs_iv);

		// set the next request public key in memory and return the body
		this.objKeys.next_pub = decrypted.nextPub;
		return decrypted.data;
	}

}
