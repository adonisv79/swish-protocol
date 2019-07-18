import { default as crypto, BinaryLike, generateKeyPairSync } from "crypto";
const _supported_rsa_sizes = [512, 1024, 2048, 4096];
export type Algorithms = 'aes-128-cbc';
export type RsaSizes = 512 | 1024;
export type SwhsHeaders = {
	swhs_action: string;
	swhs_key: string;
	swhs_iv: string;
	swhs_next: string;
	swhs_sess_id: string;
}
	
export default class HybridCryptography {

	/**
	 * This function validates the required header fields for all SWHS handshake and transactions
	 * @param headers - the HTTP Headers in the request
	 */
	validateSwhsHeader(headers: SwhsHeaders){

        if (typeof headers != 'object'){
            throw new Error("HEADER_SWHS_OBJECT_INVALID");
        } else if (!headers.swhs_action) {
            throw new Error("HEADER_SWHS_ACTION_INVALID");
        } else if (!headers.swhs_key) {
            throw new Error("HEADER_SWHS_KEY_INVALID");
        } else if (!headers.swhs_iv) {
            throw new Error("HEADER_SWHS_IV_INVALID");
        } else if (!headers.swhs_next) {
            throw new Error("HEADER_SWHS_NEXT_INVALID");
        } else {
			return true;
		}
    }

	/**
	 * Applies AES Encryption using an AES key and iv and returns the encrypted data (in base64 form)
	 * @param data The data to encrypt
	 * @param key The AES Key (should be byte array, but if its a base64 string, it is cast to a byte array)
	 * @param iv The AES Initialization Vector (should be byte array, but if its a base64 string, it is cast to a byte array)
	 * @param algorithm The algorithm to use (optional and defaults to aes-128-cbc)
	 * @returns {string} The encrypted data cast into a base64 string
	 */
	aesEncrypt(
		data: BinaryLike , 
		key: Buffer | string, 
		iv: Buffer | string, 
		algorithm: Algorithms = 'aes-128-cbc') {

		if (typeof key === 'string') key = Buffer.from(key, "base64");
		if (typeof iv === 'string') iv = Buffer.from(iv, "base64");
		let cipher = crypto.createCipheriv(algorithm, key, iv);
		let enc_data = cipher.update(data);
		return Buffer.concat([enc_data, cipher.final()]).toString('base64');
	}

	/**
	 * Applies AES Decryption to the base64+AES encrypted data using an AES key and iv and returns the decrypted data in its original form)
	 * @param enc_data The encrypted data to decrypt
	 * @param is_json Indicates if it was originally a JSON object, if true then it will be returned as JSON
	 * @param key the AES Key (should be byte array, but if its a base64 string, it is cast to a byte array)
	 * @param iv the AES Initialization Vector (should be byte array, but if its a base64 string, it is cast to a byte array)
	 * @param algorithm The algorithm to use (optional and defaults to aes-128-cbc)
	 * @returns {string | object}
	 */
	aesDecrypt(
		enc_data: string, 
		is_json: boolean = false, 
		key: Buffer | string, 
		iv: Buffer | string, 
		algorithm: Algorithms = 'aes-128-cbc') {

		if (typeof key === 'string') key = Buffer.from(key, "base64");
		if (typeof iv === 'string') iv = Buffer.from(iv, "base64");
		const enc_data_buff = Buffer.from(enc_data, "base64");
		const decipher = crypto.createDecipheriv(algorithm, key, iv);
		const dec_data_buff = decipher.update(enc_data_buff);
		let dec_data: string | Buffer = Buffer.concat([dec_data_buff, decipher.final()]).toString();
		if (is_json) dec_data = JSON.parse(dec_data);
		return dec_data;
	}

	/**
	 * Creates a new AES Key Set
	 * @param algorithm - The algorithm to use (optional and defaults to aes-128-cbc)
	 * @returns {{iv: *, key: *}}
	 */
	createAESEncryptionKey(algorithm: Algorithms = 'aes-128-cbc') {

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

	/**
	 * Creates a new RSA key pair
	 * @param passphrase - The special passphrase to use the decryption/private key
	 * @param algorithm - The algorithm to use (optional and defaults to aes-128-cbc)
	 * @param modulus_length - The modulus length to use (optional and defaults to 512)
	 * @returns {{public_key: CryptoKey | string, private_key: CryptoKey}}
	 */
	createRSAEncrytptionKey(
		passphrase: string, 
		algorithm: Algorithms = 'aes-128-cbc', 
		modulus_length: RsaSizes = 512) {

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
	 * Hybrid Decrypts the encrypted data
	 * @param enc_data - The encrypted data to decrypt
	 * @param is_json - Indicates if it was originally a JSON object, if true then it will be returned as JSON
	 * @param rsa_next_pub - the encrypted next message encryption key in the chain that we need to decrypt
	 * @param private_key - the RSA private key used to decrypt the enc_data
	 * @param passphrase - the Passphrase used to generate the RSA private key
	 * @param key - the AES Key (should be byte array, but if its a base64 string, it is cast to a byte array)
	 * @param iv - the AES Initialization Vector (should be byte array, but if its a base64 string, it is cast to a byte array)
	 * @param algorithm - The algorithm to use (optional and defaults to aes-128-cbc)
	 * @returns {{next_pub: string, data: string}}
	 */
	hybridDecrypt(
		enc_data: string, 
		is_json: boolean = false, 
		rsa_next_pub: string, 
		private_key: Buffer, 
		passphrase: string, 
		key: Buffer | string, 
		iv: Buffer | string, 
		algorithm: Algorithms = 'aes-128-cbc') {

		try{
			//decrypt the base64 AES key and IV
			if (typeof key === 'string') key = Buffer.from(key, "base64");
			key = crypto.privateDecrypt({ key: private_key, passphrase } , key);
			if (typeof iv === 'string') iv = Buffer.from(iv, "base64");
			iv = crypto.privateDecrypt({ key: private_key, passphrase } , iv);
			const next_pub = this.aesDecrypt(rsa_next_pub,false, key, iv);

			let data;
			if (enc_data) {
				data = this.aesDecrypt(enc_data, is_json, key, iv)
			}
			return { data, next_pub };
		} catch (err) {
			throw new Error(err.message);
		}
	}

	/**
	 * HybridEncrypts the data
	 * @param data - The data to encrypt
	 * @param rsa_pub - The RSA public key to be used to encrypt the data
	 * @param algorithm - The algorithm to use (optional and defaults to aes-128-cbc)
	 * @param modulus_length - The modulus length to use (optional and defaults to 512)
	 * @returns {{next_prv: CryptoKey, is_json: boolean, next_pub: string, created_date: number, enc_data: string, iv: *, key: *}}
	 */
	hybridEncrypt(data: BinaryLike | object, 
		rsa_pub: Buffer | string, 
		algorithm: Algorithms = 'aes-128-cbc', 
		modulus_length: RsaSizes = 512) {
		try{
			let is_json = false;
			if (typeof data === 'object') { //cast JSON objects to stringified json
				is_json = true;
				data = JSON.stringify(data);
			}

			//lets create the next RSA public key to use (Double Ratchet)
			const date = new Date();
			const rsa_keys = this.createRSAEncrytptionKey(date.getTime().toString(), algorithm, modulus_length);
			//create a new symetric key set
			const aes_set = this.createAESEncryptionKey(algorithm);
			//encrypt the data and next public key with the AES symetric key
			const enc_data = this.aesEncrypt(data, aes_set.key, aes_set.iv);
			const next_pub = this.aesEncrypt(rsa_keys.public_key, aes_set.key, aes_set.iv);
			//now encrypt the aes key+iv with the public key and make each base64
			const iv  = crypto.publicEncrypt(rsa_pub, aes_set.iv).toString('base64');
			const key = crypto.publicEncrypt(rsa_pub, aes_set.key).toString('base64');
			
			return {
				is_json, key, iv, next_pub,
				next_prv: rsa_keys.private_key,
				created_date: date.getTime(),
				enc_data
			}
		} catch (err) {
			throw new Error(err.message);
		}
	}
	
};