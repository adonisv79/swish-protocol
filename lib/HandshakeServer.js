const HybridCryptography = require('./HybridCryptography');
const HANDSHAKE_PATH = 'auth/handshake';

module.exports = class HandshakeServer extends HybridCryptography {
	
	static get path() {
		return HANDSHAKE_PATH;
	}
	
	get path() {
		return HANDSHAKE_PATH;
	}
	
	constructor(config) {
		super()
		//set the default
		this._config = {
			algorithm: 'aes-128-cbc',
			rsa_modulus_length: 512
		}
		
		if (config){
			if (config.algorithm && this.SUPPORTED_ALGORITHMS.indexOf(config.algorithm) == -1) {
				throw new Error("Handshake algorithm provided invalid");
			} else if (config.rsa_modulus_length && this.SUPPORTED_RSA_SIZES.indexOf(config.rsa_modulus_length) == -1) {
				throw new Error("Handshake host port provided is not valid");
			}
			Object.assign(this._config, config)
		}
	}
	
	handleHandshakeRequest(header, body, session_id) {
		//validate the header and body
		if (!header.swhs_algorithm) {
			throw new Error("HANDSHAKE_INVALID: Missing header swhs_algorithm");
		} else if (this.SUPPORTED_ALGORITHMS.indexOf(header.swhs_algorithm) == -1) {
			throw new Error("HANDSHAKE_INVALID: Invalid swhs_algorithm value");
		} else if (!header.swhs_key) {
			throw new Error("HANDSHAKE_INVALID: Missing header swhs_key");
		} else if (!header.swhs_iv) {
			throw new Error("HANDSHAKE_INVALID: Missing header swhs_iv");
		//} else if (!body.rsa_modulus_length) {
		//	throw new Error("HANDSHAKE_INVALID: Missing rsa_modulus_length value");
		//} else if (this.SUPPORTED_RSA_SIZES.indexOf(body.rsa_modulus_length) == -1) {
			//throw new Error("HANDSHAKE_INVALID: Invalid algorithm value");
		} else if (!body.enc_body) {
			throw new Error("HANDSHAKE_INVALID: Missing encrypted body");
		}
		
		//first lets decrypt that public key for sending our responses to this client
		const response_pub_key = this.aesDecrypt(
			header.swhs_algorithm, 
			header.swhs_key, 
			header.swhs_iv, 
			body.enc_body, 
			body.is_json)
	
		
		//now we will tell the client how it will send us an encrypted request
		const date = new Date()
		const RSA = { created_date: date.getTime() }
		
		//lets create our own key sets for this session. The passphrase is the created date
		const rsa_keys = this.createRSAEncrytptionKey(RSA.created_date, this._config.rsa_modulus_length, this._config.algorithm)
		RSA.private_key = rsa_keys.private_key;
		
		//encrypt the request public key using the client's response public key
		const result = this.encryptResponse(session_id, response_pub_key, rsa_keys.public_key)
		result.session_keys = {
			response_pub_key,
			request: RSA
		}
		return result
	}
	
	/**
	* Decrypt the encrypted request with the session private key
	*/
	decryptRequest(private_key, passphrase, data) {
		let body = this.hybridDecrypt(
			data.SWHS_ALGORITHM, 
			private_key, 
			passphrase, 
			data.SWHS_KEY, 
			data.SWHS_IV,
			data.enc_body);
		
		//convert to JSON if it was originaly sent as JSON
		if (data.is_json) { body = JSON.parse(body); }
		return body;
	}
	
	
	/**
	* Encrypt the response with the session public key
	*/
	encryptResponse(swhs_sess_id, public_key, body) {
		if (!public_key) {
			throw new Error('PUBLIC_KEY_INVALID')
		} else if (!body) { 
			throw new Error('BODY_INVALID')
		}
		const result = this.hybridEncrypt(this._config.algorithm, public_key, body)
		return {
			headers: {
				'SWHS_SESS_ID': swhs_sess_id,
				'SWHS_ALGORITHM': this._config.algorithm,
				'SWHS_KEY': result.key,
				'SWHS_IV': result.iv
			},
			body: {
				is_json: result.is_json,
				enc_body: result.enc_body
			}
		}
	}
}