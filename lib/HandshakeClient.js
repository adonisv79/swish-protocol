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
		return (this._keys && this._keys.request);
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
	
	generateHandshake() {
		const aes_set = this.createAESEncryptionKey(this._config.algorithm);
		const new_pub_key = this.aesEncrypt(
			this._config.algorithm, 
			aes_set.key, 
			aes_set.iv, 
			this._keys.response.public_key);
		
		return {
			headers: {
                SWHS_SESS_ID: '',
                SWHS_ACTION: 'handshake_init',
				SWHS_ALGORITHM: this._config.algorithm,
				SWHS_KEY: aes_set.key.toString('base64'),
                SWHS_IV: aes_set.iv.toString('base64'),
                SWHS_NEXT: new_pub_key
			},
			body: {
				is_json: false
			}
		}
	}
	
	/**
	* Resets the existing keys (if any)
	*/
	resetKeys() {
		const date = new Date();
		this._session_id = null;
		this._keys = {
			created_date: date.getTime()
		};
		//create a new pub-prv key and lets make the 1 time use passphrase based on time created
		this._keys.response = this.createRSAEncrytptionKey(this._keys.created_date, this._config.rsa_modulus_length, this._config.algorithm)
	}
	
	/**
	* Pairs a session keys with the existing one
	*/
	handleHandshakeResponse(headers, res_body) {
        //validate the header and ensure request is for handshake
        this.validateSwhsHeader(headers);
		const date = new Date();
		if (!headers.swhs_sess_id) {
            throw new Error("HANDSHAKE_INVALID: Missing header swhs_sess_id");
        } else if (this._session_id && this._session_id !== headers.swhs_sess_id) {
            throw new Error("HANDSHAKE_INVALID: Session ID mismatch");
		}
		//if new session id, assign it
		if (!this._session_id && headers.swhs_sess_id) this._session_id = headers.swhs_sess_id;

		//retrieve the next request sequenced pub key
		const request_pub_key = this.decryptResponse(headers, res_body);
		
		this._keys.request = {
			retrieved_date: date.getTime(),
			public_key: request_pub_key
		};
		return this._keys;
	}
	
	encryptRequest(body) {
		if (!body) { 
			throw new Error('BODY_INVALID')
		} else if (!this._keys || !this._keys.next_pub) {
			throw new Error('Next public request key is not set!')
		}

		const result = this.hybridEncrypt(this._config.algorithm, this._config.rsa_modulus_length, this._keys.next_pub, body);
		
		return {
			headers: {
				SWHS_SESS_ID: this._session_id,
				SWHS_ALGORITHM: this._config.algorithm,
				SWHS_KEY: result.key,
                SWHS_IV: result.iv,
                SWHS_NEXT: result.next_pub,
			},
			body: {
				is_json: result.is_json,
				enc_body: result.enc_body
			},
			decrypt: {
                next_prv: result.next_prv,
                created_date: result.created_date
			}
		}
	}
	
	/**
	* Decrypt the encrypted response
	*/
	decryptResponse(header, response_body) {
		let result = this.hybridDecrypt(
            header.swhs_algorithm,
			this._keys.response.private_key, 
			this._keys.created_date,
            header.swhs_key,
            header.swhs_iv,
            header.swhs_next,
            response_body.enc_body);
		
		//convert to JSON if it was originaly sent as JSON
		if (result.body && response_body.is_json) {
			result.body = JSON.parse(result.body);
		}

		//set the next request public key in memory and return the body
		this._keys.next_pub = result.next_pub;
		return result.body;
	}
};