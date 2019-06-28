const { URL } = require('url');
const net = require('net');
const HybridCryptography = require('./HybridCryptography');
const HANDSHAKE_PATH = 'auth/handshake';
const _supported_protocols = ['http', 'https']

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
		super()
		//set the default
		this._keys = null;
		this._session_id = null;
		this._config = {
			algorithm: 'aes-128-cbc',
			handshake_protocol: 'http',
			handshake_ip: 'localhost',
			handshake_port: 80,
			rsa_modulus_length: 512
		}
		
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
			Object.assign(this._config, config)
			this._config.connect_uri = new URL(this._config.handshake_protocol + '://' + this._config.handshake_ip + ':' + this._config.handshake_port);		
		}
	}
	
	generateHandshake() {
		const aes_set = this.createAESEncryptionKey(this._config.algorithm)
		const enc_body = this.aesEncrypt(
			this._config.algorithm, 
			aes_set.key, 
			aes_set.iv, 
			this._keys.response.public_key)
		
		return {
			headers: {
				SWHS_SESS_ID: '',
				SWHS_ALGORITHM: this._config.algorithm,
				SWHS_KEY: aes_set.key.toString('base64'),
				SWHS_IV: aes_set.iv.toString('base64')
			},
			body: {
				is_json: false,
				enc_body
			}
		}
	}
	
	/**
	* Resets the existing keys (if any)
	*/
	resetKeys() {
		const date = new Date()
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
	handleHandshakeResponse(handshake_pairing) {
		const date = new Date()
		if (!this._keys || !this._keys.response) {
			throw new Error('No response key exist. please run resetKeys() first')
		} else if (!handshake_pairing || typeof handshake_pairing != 'object') {
			throw new Error('Pairing object invalid')
		} else if (!handshake_pairing.SWHS_SESS_ID) {
			throw new Error('Pairing object requires a Session identifier (session_id) value to track sessions')
		} else if (!handshake_pairing.SWHS_ALGORITHM) {
			throw new Error('Pairing object algorithm not provided')
		} else if (!handshake_pairing.SWHS_KEY) {
			throw new Error('Pairing object key value is invalid')
		} else if (!handshake_pairing.SWHS_IV) {
			throw new Error('Pairing object iv value is invalid')
		} else if (!handshake_pairing.enc_body) {
			throw new Error('Pairing object enc_body value is invalid')
		}
		
		//store the session identifier
		this._session_id = handshake_pairing.SWHS_SESS_ID;
		const request_pub_key = this.decryptResponse(handshake_pairing)
		
		this._keys.request = {
			retrieved_date: date.getTime(),
			public_key: request_pub_key
		}
		return this._keys;
	}
	
	encryptRequest(body) {
		if (!body) { 
			throw new Error('BODY_INVALID')
		} else if (!this._keys || !this._keys.request || !this._keys.request.public_key) {
			throw new Error('No server auth pairing exists. run pairKeys() function first.')
		}

		const enc = this.hybridEncrypt(this._config.algorithm, this._keys.request.public_key, body)
		
		return {
			headers: {
				SWHS_SESS_ID: this._session_id,
				SWHS_ALGORITHM: this._config.algorithm,
				SWHS_KEY: enc.key,
				SWHS_IV: enc.iv,
			},
			body: {
				is_json: enc.is_json,
				enc_body: enc.enc_body
			}
		}
	}
	
	/**
	* Decrypt the encrypted response
	*/
	decryptResponse(target) {
		let body = this.hybridDecrypt(
			target.SWHS_ALGORITHM, 
			this._keys.response.private_key, 
			this._keys.created_date, 
			target.SWHS_KEY, 
			target.SWHS_IV,
			target.enc_body);
		
		//convert to JSON if it was originaly sent as JSON
		if (target.is_json) { body = JSON.parse(body); }
		return body;
	}
}