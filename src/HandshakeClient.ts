import {default as HybridCryptography, SwhsHeaders, SwhsBody} from "./HybridCryptography";
import { BinaryLike } from "crypto";

export default class HandshakeClient extends HybridCryptography{
	_session_id!: string;
	_keys: {
		next_pub: Buffer | string,
		next_prv: Buffer | string,
		created_date: number
	}

	/**
	 * Gets the current client session id
	 * @returns {null}
	 */
	public get sessionId(): string {
		return this._session_id;
	}

	constructor() {
		super();
		//set the default
		this._keys = { next_pub: "", next_prv: "", created_date: -1 };
		this._session_id = "";
	}

	/**
	 * Validates the headers with added keys expected from a server response
	 * @param headers
	 */
	public validateResponseSwhsHeader(headers: SwhsHeaders): void {
		this.validateSwhsHeader(headers);

		if (!headers.swhs_sess_id) {
			throw new Error("HANDSHAKE_INVALID: Missing header swhs_sess_id");
		} else if (this._session_id && this._session_id !== headers.swhs_sess_id) {
			throw new Error("HANDSHAKE_INVALID: Session ID mismatch");
		}
	}

	/**
	 * Generates a new handshake request and retrieve the next generated SWHS header values
	 * @returns {{headers: {swhs_iv: string, swhs_action: string, swhs_sess_id: string, swhs_key: string, swhs_next: string}, body: {is_json: boolean}}}
	 */
	public generateHandshake(): { headers: SwhsHeaders, body: SwhsBody} {
		//create a new RSA key pair
		const date = new Date();
		const rsa = this.createRSAEncrytptionKey(date.getTime().toString());
		this._session_id = "";
		this._keys = {
			created_date: date.getTime(),
			next_prv: rsa.private_key,
			next_pub: rsa.public_key
		};

		//create a new aes set to encrypt the "response public key"
		const aes_set = this.createAESEncryptionKey();
		const enc_next_pub = this.aesEncrypt(
			this._keys.next_pub,
			aes_set.key, 
			aes_set.iv);
		
		return {
			headers: {
				swhs_sess_id: '',
				swhs_action: 'handshake_init',
				swhs_key: aes_set.key.toString('base64'),
				swhs_iv: aes_set.iv.toString('base64'),
				swhs_next: enc_next_pub
			},
			body: {
				is_json: false
			}
		}
	}

	/**
	 * Encrypts a request body and retrieve the next generated SWHS header values
	 * @param body - the request body to encrypt
	 * @returns {{headers: {swhs_iv: *, swhs_sess_id: null, swhs_key: *, swhs_next: string}, body: {is_json: boolean, enc_body}}}
	 */
	public encryptRequest(body: BinaryLike | object): { headers: SwhsHeaders, body: SwhsBody } {
		if (!body) {
			throw new Error('BODY_INVALID')
		} else if (!this._keys || !this._keys.next_pub) {
			throw new Error('Next public request key is not set!')
		}

		const result = this.hybridEncrypt(body, this._keys.next_pub);
		this._keys.next_prv = result.next_prv;
		this._keys.created_date = result.created_date;

		return {
			headers: {
				swhs_sess_id: this._session_id,
				swhs_action: 'request_basic',
				swhs_key: result.key,
				swhs_iv: result.iv,
				swhs_next: result.next_pub, //this is the next response
			},
			body: {
				is_json: result.is_json,
				enc_body: result.enc_data
			}
		}
	}

	/**
	 * Handle the response from the SWHS service and stores the next pub key in the chain
	 * @param headers - The response headers
	 * @param body - The response body
	 * @returns {string}
	 */
	public handleHandshakeResponse(headers: SwhsHeaders, body: SwhsBody) {
		console.dir(body)
		//if new session id, assign it
		if (!this._session_id && headers.swhs_sess_id) this._session_id = headers.swhs_sess_id;
		//retrieve the next request sequenced pub key
		return this.decryptResponse(headers, body);
	}

	/**
	 * Decrypt the encrypted response and stores the next pub key in the chain
	 * @param headers - The response headers
	 * @param body - The response body
	 * @returns {string}
	 */
	public decryptResponse(headers:SwhsHeaders, body: SwhsBody) {
		try {
			this.validateResponseSwhsHeader(headers);
			let decrypted = this.hybridDecrypt(
				body,
				headers.swhs_next,
				this._keys.next_prv,
				this._keys.created_date.toString(),
				headers.swhs_key,
				headers.swhs_iv);

			//set the next request public key in memory and return the body
			this._keys.next_pub = decrypted.next_pub;
			return decrypted.data;
		} catch (err) {
			throw err.message;
		}
	}

};