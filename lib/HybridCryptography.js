const crypto = require('crypto');
const { generateKeyPairSync  } = require('crypto');
const _supported_algorithms = ['aes-128-cbc']; //todo: 'aes-192-cbc', 'aes-256-cbc' are not yet working
const _supported_rsa_sizes = [512, 1024, 2048, 4096];

	
module.exports = class HybridCryptography {
	
	get SUPPORTED_RSA_SIZES() {
		return _supported_rsa_sizes
	}
	
	get SUPPORTED_ALGORITHMS() {
		return _supported_algorithms
	}

    /**
     * This function validates the required header fields for all SWHS handshake and transactions
     * @param header - the complete header object from the request
     */
    validateSwhsHeader(header){
        if (typeof header != 'object'){
            throw new Error("HANDSHAKE_INVALID: Header object invalid type");
		} else if (!header.swhs_algorithm) {
            throw new Error("HANDSHAKE_INVALID: Missing header swhs_algorithm");
        } else if (!header.swhs_action) {
            throw new Error("HANDSHAKE_INVALID: Invalid swhs_action value");
        } else if (this.SUPPORTED_ALGORITHMS.indexOf(header.swhs_algorithm) == -1) {
            throw new Error("HANDSHAKE_INVALID: Invalid swhs_algorithm value");
        } else if (!header.swhs_key) {
            throw new Error("HANDSHAKE_INVALID: Missing header swhs_key");
        } else if (!header.swhs_iv) {
            throw new Error("HANDSHAKE_INVALID: Missing header swhs_iv");
        } else if (!header.swhs_next) {
            throw new Error("HANDSHAKE_INVALID: Missing header swhs_next");
        }
    }

	/**
	* applies AES Encryption using an key and iv (in base 64 format)
	* and returns the encrypted body in base64 form)
	*/
	aesEncrypt(algorithm, key, iv, body) {
		if (typeof key === 'string') key = Buffer.from(key, "base64");
		if (typeof iv === 'string') iv = Buffer.from(iv, "base64");
		let cipher = crypto.createCipheriv(algorithm, key, iv);
		let enc_body = cipher.update(body);
		return Buffer.concat([enc_body, cipher.final()]).toString('base64');
	}

	/**
	* applies AES Decryption to the base64+AES encrypted body
	* using an key and iv (in base 64 format)
	* and returns the decrypted body in its original form)
	*/
	aesDecrypt(algorithm, key, iv, enc_body, is_json) {
		if (typeof key === 'string') key = Buffer.from(key, "base64");
		if (typeof iv === 'string') iv = Buffer.from(iv, "base64");
		enc_body = Buffer.from(enc_body, "base64");
		let decipher = crypto.createDecipheriv(algorithm, key, iv);
		let body = decipher.update(enc_body);
		body = Buffer.concat([body, decipher.final()]).toString();
		if (is_json) body = JSON.parse(body);
		return body
	}
	
	createAESEncryptionKey(algorithm) {
		let size;
		switch(algorithm) {
			case 'aes-128-cbc':
				size = 16; //16 bytes or 128 bits
				break;
			default:
				throw new Error('Algorithm not supported');
		}
		//generate the new random key and IV which should be of same size
		return { key: crypto.randomBytes(size), iv: crypto.randomBytes(size) }
	}
	
	createRSAEncrytptionKey(passphrase, modulus_length, algorithm) {
		if (_supported_rsa_sizes.indexOf(modulus_length) == -1) {
			throw new Error('INVALID_MODULUS_LENGTH');
		}
		const keys = generateKeyPairSync('rsa', {
			modulusLength: modulus_length,
			publicKeyEncoding: {
				type: 'spki',
				format: 'pem'
			},
			privateKeyEncoding: {
				type: 'pkcs8',
				format: 'pem',
				cipher: algorithm,
				passphrase: passphrase.toString()
			}
		});
		//just so we do not break our naming convention
		return {
			public_key: keys.publicKey,
			private_key: keys.privateKey,
		}
	}

	/**
	 * Decrypts the encrypted body
	 * @param algorithm
	 * @param private_key
	 * @param passphrase
	 * @param aes_key
	 * @param aes_iv
	 * @param rsa_next_pub - this is the next request public key in the chain
	 * @param enc_body
	 * @returns {{next_pub: void | Promise<void> | never | IDBRequest<IDBValidKey>, body: void | Promise<void> | IDBRequest<IDBValidKey>}}
	 */
	hybridDecrypt(algorithm, private_key, passphrase, aes_key, aes_iv, rsa_next_pub, enc_body, body_is_json) {
		try{
			//decrypt the base64 AES key and IV
			const aes_key_bytes = Buffer.from(aes_key, "base64");
			const key = crypto.privateDecrypt({ key: private_key, passphrase } , aes_key_bytes);
			const aes_iv_bytes = Buffer.from(aes_iv, "base64");
			const iv = crypto.privateDecrypt({ key: private_key, passphrase } , aes_iv_bytes);

			//decrypt the next request pub key
            const rsa_next_pub_bytes = Buffer.from(rsa_next_pub, 'base64');
			const next_pub = this.aesDecrypt(algorithm, key, iv, rsa_next_pub_bytes);

			let body;
			if (enc_body) {
                //decrypt the Base64 AES encrypted request key (server public key)
                const enc_body_bytes = Buffer.from(enc_body, 'base64');
                body = this.aesDecrypt(algorithm, key, iv, enc_body_bytes, body_is_json)
			}
			return { body, next_pub };
		} catch (err) {
			throw new Error('HYBRID_DECRYPT_FAILED');
		}
	}

	hybridEncrypt(body, send_pub_key, algorithm = 'aes-128-cbc', rsa_modulus_length = 512) {
		try{
			let is_json = false;
			if (typeof body === 'object') {
				is_json = true;
				body = JSON.stringify(body);
			}

			//lets create the next RSA public key to use (Double Ratchet)
			const date = new Date();
			const rsa_keys = this.createRSAEncrytptionKey(date.getTime(), rsa_modulus_length, algorithm);
			//create a new symetric key set
			const aes_set = this.createAESEncryptionKey(algorithm);
			//encrypt the body and next public key with the AES symetric key
			const enc_body = this.aesEncrypt(algorithm, aes_set.key, aes_set.iv, body);
			const next_pub = this.aesEncrypt(algorithm, aes_set.key, aes_set.iv, rsa_keys.public_key);
			//now encrypt the aes key+iv with the public key and make each base64
			const iv  = crypto.publicEncrypt(send_pub_key, aes_set.iv).toString('base64');
			const key = crypto.publicEncrypt(send_pub_key, aes_set.key).toString('base64');
			
			return {
				is_json, key, iv, next_pub,
				next_prv: rsa_keys.private_key,
				created_date: date.getTime(),
				enc_body
			}
		} catch (err) {
			throw new Error('HYBRID_ENCRYPT_FAILED');
		}
	}
	
};