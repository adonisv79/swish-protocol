const { URL } = require('url');
const net = require('net');
const HybridCryptography = require('./HybridCryptography');
const HANDSHAKE_PATH = 'auth/handshake';
const _supported_protocols = ['http', 'https'];

module.exports = class HandshakeClient extends HybridCryptography{
	
	get sessionId() {
		return this._session_id;
	}
	
	get uri() {
		return this._config.connect_uri.href;
	}
	
	get uri_auth() {
		return this._config.connect_uri.href + HANDSHAKE_PATH;
	}
	
	/**
	* Returns true if we have an existing key pairing with an API server/host
	*/
	get isPaired() {
		return (this._keys && this._keys.next_pub);
	}
	
	constructor(config) {
		super();
		//set the default
		this._keys = null;
		this._session_id = null;
		this._config = {
			algorithm: 'aes-128-cbc',
			handshake_protocol: 'http',
			handshake_ip: 'localhost',
			handshake_port: 80,
			rsa_modulus_length: 512
		};
		
		if (config) {
			if (config.algorithm && this.SUPPORTED_ALGORITHMS.indexOf(config.algorithm) == -1) {
				throw new Error("Handshake algorithm provided invalid");
			} else if (config.handshake_protocol && _supported_protocols.indexOf(config.handshake_protocol) == -1) {
				throw new Error("Handshake protocol provided is not supported");
			} else if (config.handshake_ip && !net.isIP(config.handshake_ip) > 0) {
				throw new Error("Handshake host IP provided not valid");
			} else if (config.handshake_port && (config.handshake_port < 1 || config.handshake_port > 65535)) {
				throw new Error("Handshake host port provided is not valid");
			} else if (config.rsa_modulus_length && this.SUPPORTED_RSA_SIZES.indexOf(config.rsa_modulus_length) == -1) {
				throw new Error("Handshake host port provided is not valid");
			}
			Object.assign(this._config, config);
			this._config.connect_uri = new URL(this._config.handshake_protocol + '://' + this._config.handshake_ip + ':' + this._config.handshake_port);		
		}
	}

	/**
	 * Validates the headers with added keys expected from a server response
	 * @param headers
	 */
	validateResponseSwhsHeader(headers) {
		this.validateSwhsHeader(headers);

		if (!headers.swhs_sess_id) {
			throw new Error("HANDSHAKE_INVALID: Missing header swhs_sess_id");
		} else if (this._session_id && this._session_id !== headers.swhs_sess_id) {
			throw new Error("HANDSHAKE_INVALID: Session ID mismatch");
		}
	}

	/**
	 * Generates a new handshake request key set
	 * @returns {{headers: {swhs_key: string, swhs_iv: string, swhs_action: string, swhs_algorithm: string, swhs_next, swhs_sess_id: string}, body: {is_json: boolean}}}
	 */
	generateHandshake() {
		//create a new RSA key pair
		const date = new Date();
		const rsa = this.createRSAEncrytptionKey(date.getTime());
		this._session_id = null;
		this._keys = {
			created_date: date.getTime(),
			next_prv: rsa.private_key,
			next_pub: rsa.public_key
		};

		//create a new aes set to encrypt the "response public key"
		const aes_set = this.createAESEncryptionKey(this._config.algorithm);
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

	encryptRequest(body) {
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
				swhs_algorithm: this._config.algorithm,
				swhs_key: result.key,
				swhs_iv: result.iv,
				swhs_next: result.next_pub, //this is the next response
			},
			body: {
				is_json: result.is_json,
				enc_body: result.enc_body
			}
		}
	}
	
	/**
	* Pairs a session keys with the existing one
	*/
	handleHandshakeResponse(headers, res_body) {
		//if new session id, assign it
		if (!this._session_id && headers.swhs_sess_id) this._session_id = headers.swhs_sess_id;
		//retrieve the next request sequenced pub key
		const body = this.decryptResponse(headers, res_body);
		return body;
	}
	
	/**
	* Decrypt the encrypted response
	*/
	decryptResponse(headers, response_body) {
		this.validateResponseSwhsHeader(headers);
		let result = this.hybridDecrypt(
			response_body.enc_body,
			response_body.is_json,
			headers.swhs_next,
			this._keys.next_prv,
			this._keys.created_date,
			headers.swhs_key,
			headers.swhs_iv);

		//set the next request public key in memory and return the body
		this._keys.next_pub = result.next_pub;
		return result.body;
	}

};