const { URL } = require('url');
const net = require('net');
const HybridCrypto = require('./HybridCryptography');
const HANDSHAKE_PATH = 'auth/handshake';
const _supported_protocols = ['http', 'https']

module.exports = class HandshakeClient {
	
	get sessionId() {
		return this._session_id;
	}
	
	get uri() {
		return this._config.connect_uri.href;
	}
	
	get uri_auth() {
		return this._config.connect_uri.href + HANDSHAKE_PATH;
	}
	
	get handshakeBody() {
		return {
			algorithm: this._config.algorithm,
			rsa_modulus_length: this._config.rsa_modulus_length,
			client_pub_key: this._keys.response.public_key
		}
	}
	
	/**
	* Returns true if we have an existing key pairing with an API server/host
	*/
	get isPaired() {
		return (this._keys && this._keys.request);
	}
	
	constructor(config) {
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
			if (config.algorithm && HybridCrypto.SUPPORTED_ALGORITHMS.indexOf(config.algorithm) == -1) {
				throw new Error("Handshake algorithm provided invalid");
			} else if (config.handshake_protocol && _supported_protocols.indexOf(config.handshake_protocol) == -1) {
				throw new Error("Handshake protocol provided is not supported");
			} else if (config.handshake_ip && !net.isIP(config.handshake_ip) > 0) {
				throw new Error("Handshake host IP provided not valid");
			} else if (config.handshake_port && (config.handshake_port < 1 || config.handshake_port > 65535)) {
				throw new Error("Handshake host port provided is not valid");
			} else if (config.rsa_modulus_length && HybridCrypto.SUPPORTED_RSA_SIZES.indexOf(config.rsa_modulus_length) == -1) {
				throw new Error("Handshake host port provided is not valid");
			}
			Object.assign(this._config, config)
			this._config.connect_uri = new URL(this._config.handshake_protocol + '://' + this._config.handshake_ip + ':' + this._config.handshake_port);		
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
		this._keys.response = HybridCrypto.createRSAEncrytptionKey(this._keys.created_date, this._config.rsa_modulus_length, this._config.algorithm)
	}
	
	/**
	* Pairs a session keys with the existing one
	*/
	handleHandshakeResponse(enc_body) {
		const date = new Date()
		if (!this._keys || !this._keys.response) {
			throw new Error('No response key exist. please run resetKeys() first')
		} else if (!enc_body && typeof enc_body != 'object') {
			throw new Error('Pairing object invalid')
		} else if (!enc_body.session_id) {
			throw new Error('Pairing object requires a Session identifier (session_id) value to track sessions')
		} else if (!enc_body.enc_body) {
			throw new Error('Pairing object enc_body value is invalid')
		} else if (!enc_body.key) {
			throw new Error('Pairing object key value is invalid')
		} else if (!enc_body.iv) {
			throw new Error('Pairing object iv value is invalid')
		}
		//store the session identifier
		this._session_id = enc_body.session_id;
		const body = this.decryptResponse(enc_body)
		
		this._keys.request = {
			retrieved_date: date.getTime(),
			public_key: body
		}
		return this._keys;
	}
	
	encryptRequest(body) {
		if (!body) { 
			throw new Error('BODY_INVALID')
		} else if (!this._keys || !this._keys.request || !this._keys.request.public_key) {
			throw new Error('No server auth pairing exists. run pairKeys() function first.')
		}

		const enc = HybridCrypto.hybridEncrypt(this._config.algorithm, this._keys.request.public_key, body)
		
		return {
			session_id: this._session_id,
			is_json: enc.is_json,
			key: enc.key,
			iv: enc.iv,
			enc_body: enc.enc_body
		}
	}
	
	/**
	* Decrypt the encrypted response
	*/
	decryptResponse(enc_body) {
		let body = HybridCrypto.hybridDecrypt(
			this._config.algorithm, 
			this._keys.response.private_key, 
			this._keys.created_date, 
			enc_body.key, 
			enc_body.iv,
			enc_body.enc_body);
		
		//convert to JSON if it was originaly sent as JSON
		if (enc_body.is_json) { body = JSON.parse(body); }
		return body;
	}
}