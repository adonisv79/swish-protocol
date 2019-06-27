const HybridCrypto = require('./HybridCryptography');
const HANDSHAKE_PATH = 'auth/handshake';

module.exports = class HandshakeServer {
	
	static get path() {
		return HANDSHAKE_PATH;
	}
	
	get path() {
		return HANDSHAKE_PATH;
	}
	
	constructor(config) {
		//set the default
		this._config = {
			algorithm: 'aes-128-cbc',
			rsa_modulus_length: 512
		}
		
		if (config){
			if (config.algorithm && HybridCrypto.SUPPORTED_ALGORITHMS.indexOf(config.algorithm) == -1) {
				throw new Error("Handshake algorithm provided invalid");
			} else if (config.rsa_modulus_length && HybridCrypto.SUPPORTED_RSA_SIZES.indexOf(config.rsa_modulus_length) == -1) {
				throw new Error("Handshake host port provided is not valid");
			}
			Object.assign(this._config, config)
		}
	}
	
	handleHandshakeRequest(body) {
		//validate the body
		if (!body.algorithm) {
			throw new Error("HANDSHAKE_INVALID: Missing algorithm value");
		} else if (HybridCrypto.SUPPORTED_ALGORITHMS.indexOf(body.algorithm) == -1) {
			throw new Error("HANDSHAKE_INVALID: Invalid algorithm value");
		} else if (!body.rsa_modulus_length) {
			throw new Error("HANDSHAKE_INVALID: Missing rsa_modulus_length value");
		} else if (HybridCrypto.SUPPORTED_RSA_SIZES.indexOf(body.rsa_modulus_length) == -1) {
			throw new Error("HANDSHAKE_INVALID: Invalid algorithm value");
		} else if (!body.client_pub_key) {
			throw new Error("HANDSHAKE_INVALID: Missing client_pub_key value");
		}
		const date = new Date()
		const RSA = { created_date: date.getTime() }
		
		//now lets create our own key sets for this session. The passphrase is the created date
		const rsa_keys = HybridCrypto.createRSAEncrytptionKey(RSA.created_date, this._config.rsa_modulus_length, this._config.algorithm)
		RSA.private_key = rsa_keys.private_key;
		
		const enc = this.encryptResponse(body.client_pub_key, rsa_keys.public_key)
		
		return {
			RSA,
			response_body: {
				key: enc.key,
				iv: enc.iv,
				enc_body: enc.enc_body
			}
		}
	}
	
	/**
	* Decrypt the encrypted request with the session private key
	*/
	decryptRequest(private_key, passphrase, enc_body) {
		let body = HybridCrypto.hybridDecrypt(
			this._config.algorithm, 
			private_key, 
			passphrase, 
			enc_body.key, 
			enc_body.iv,
			enc_body.enc_body);
		
		//convert to JSON if it was originaly sent as JSON
		if (enc_body.is_json) { body = JSON.parse(body); }
		return body;
	}
	
	
	/**
	* Encrypt the response with the session public key
	*/
	encryptResponse(public_key, body) {
		if (!public_key) {
			throw new Error('PUBLIC_KEY_INVALID')
		} else if (!body) { 
			throw new Error('BODY_INVALID')
		}
		return HybridCrypto.hybridEncrypt(this._config.algorithm, public_key, body)
	}
}