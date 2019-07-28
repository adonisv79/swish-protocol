import { BinaryLike } from "crypto";

import { HybridCryptography, SwishBody, SwishHeaders } from "./HybridCryptography";

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
	public validateResponseSwishHeader(headers: SwishHeaders): void {
		if (!headers.swish_sess_id) {
			throw new Error("HANDSHAKE_INVALID: Missing header swish_sess_id");
		} else if (this.strSessionId && this.strSessionId !== headers.swish_sess_id) {
			throw new Error("HANDSHAKE_INVALID: Session ID mismatch");
		}
	}

	/**
	 * Generates a new handshake request and retrieve the next generated SWISH header values
	 */
	public generateHandshake(): { headers: SwishHeaders; body: SwishBody} {
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
				swish_action: "handshake_init",
				swish_iv: aesSet.iv.toString("base64"),
				swish_key: aesSet.key.toString("base64"),
				swish_next: encNextPub,
				swish_sess_id: "",
			},
		};
	}

	/**
	 * Encrypts a request body and retrieve the next generated SWISH header values
	 * @param body - the request body to encrypt
	 */
	public encryptRequest(body: BinaryLike | object): { headers: SwishHeaders; body: SwishBody } {
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
				swish_action: "request_basic",
				swish_iv: result.iv,
				swish_key: result.key,
				swish_next: result.nextPub, // this is the next response
				swish_sess_id: this.strSessionId,
			},
		};
	}

	/**
	 * Handle the response from the SWISH service and stores the next pub key in the chain
	 * @param headers - The response headers
	 * @param body - The response body
	 */
	public handleHandshakeResponse(headers: SwishHeaders, body: SwishBody) {
		// if new session id, assign it
		if (!this.strSessionId && headers.swish_sess_id) {
			this.strSessionId = headers.swish_sess_id;
		}
		// retrieve the next request sequenced pub key
		return this.decryptResponse(headers, body);
	}

	/**
	 * Decrypt the encrypted response and stores the next pub key in the chain
	 * @param headers - The response headers
	 * @param body - The response body
	 */
	public decryptResponse(headers: SwishHeaders, body: SwishBody) {
		this.validateResponseSwishHeader(headers);
		const decrypted = this.hybridDecrypt(
			body,
			headers.swish_next,
			this.objKeys.next_prv,
			this.objKeys.created_date.toString(),
			headers.swish_key,
			headers.swish_iv);

		// set the next request public key in memory and return the body
		this.objKeys.next_pub = decrypted.nextPub;
		return decrypted.data;
	}

}
