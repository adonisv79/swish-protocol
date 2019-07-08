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
		super();
		//set the default
		this._config = {
			algorithm: 'aes-128-cbc',
			rsa_modulus_length: 512
		};

		if (config){
			if (config.algorithm && this.SUPPORTED_ALGORITHMS.indexOf(config.algorithm) == -1) {
				throw new Error("Handshake algorithm provided invalid");
			} else if (config.rsa_modulus_length && this.SUPPORTED_RSA_SIZES.indexOf(config.rsa_modulus_length) == -1) {
				throw new Error("Handshake host port provided is not valid");
			}
			Object.assign(this._config, config)
		}
	}


	handleHandshakeRequest(header, session_id) {
		//validate the header and ensure request is for handshake
		this.validateSwhsHeader(header);
		if (header.swhs_action !== 'handshake_init') {
			throw new Error("HANDSHAKE_INVALID: swhs_action is not handshake_init");
		}

		//first lets decrypt that public key for sending our responses to this client
		const response_pub_key = this.aesDecrypt(header.swhs_algorithm,
			header.swhs_key, header.swhs_iv, header.swhs_next, false);

		//encrypt an ok response using the client's response public key
		const result = this.encryptResponse(session_id, response_pub_key, { status: 'ok' });

		result.headers.SWHS_ACTION = 'handshake_response'; //override the action value
		return result;
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

		//use Hybrid Encryption and return the response in the proper structure
		const result = this.hybridEncrypt(this._config.algorithm, this._config.rsa_modulus_length, public_key, body);
		return {
			headers: {
				'SWHS_SESS_ID': swhs_sess_id,
				'SWHS_ALGORITHM': this._config.algorithm,
                'SWHS_ACTION': 'encrypt_response',
                'SWHS_KEY': result.key,
                'SWHS_IV': result.iv,
                'SWHS_NEXT': result.next_pub
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
};