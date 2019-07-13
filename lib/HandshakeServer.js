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
		const response_pub_key = this.aesDecrypt(header.swhs_next, false,
			header.swhs_key, header.swhs_iv);

		//encrypt an ok response using the client's response public key
		const result = this.encryptResponse(session_id, { status: 'ok' }, response_pub_key);

		result.headers.swhs_action = 'handshake_response'; //override the action value
		return result;
	}

	/**
	* Decrypt the encrypted request with the session next key set
	*/
	decryptRequest(headers, raw_body, private_key, passphrase) {
		let dec_body = this.hybridDecrypt(
            raw_body.enc_body,
            raw_body.is_json,
            headers.swhs_next,
			private_key,
			passphrase,
            headers.swhs_key,
            headers.swhs_iv);

		return dec_body;
	}


	/**
	* Encrypt the response with the session public key
	*/
	encryptResponse(swhs_sess_id, body, public_key) {
		if (!public_key) {
			throw new Error('PUBLIC_KEY_INVALID')
		} else if (!body) {
			throw new Error('BODY_INVALID')
		}

		//use Hybrid Encryption and return the response in the proper structure
		const result = this.hybridEncrypt(body, public_key);
		return {
			headers: {
				'swhs_sess_id': swhs_sess_id,
				'swhs_algorithm': this._config.algorithm,
                'swhs_action': 'encrypt_response',
                'swhs_key': result.key,
                'swhs_iv': result.iv,
                'swhs_next': result.next_pub
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