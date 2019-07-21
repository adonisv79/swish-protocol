import { BinaryLike, default as crypto, generateKeyPairSync } from "crypto";

export type Algorithms = "aes-128-cbc";
export type RsaSizes = 512 | 1024;
export interface SwhsHeaders {
	swhs_action: string;
	swhs_iv: string;
	swhs_key: string;
	swhs_next: string;
	swhs_sess_id: string;
}
const SwhsHeaderRules = {
	swhs_action: {
		maxlen: 50,
	},
};

export interface SwhsBody {
	enc_body?: string;
	is_json: boolean;
}

export class HybridCryptography {

	/**
	 * This function validates the required header fields for all SWHS handshake and transactions
	 * @param headers - the HTTP Headers in the request
	 */
	public validateSwhsHeader(headers: SwhsHeaders) {
		if (headers.swhs_action.length > SwhsHeaderRules.swhs_action.maxlen) {
			throw new Error("HEADER_SWHS_ACTION_LEN_ERR");
		}

		if (!headers.swhs_key) {
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
	 * @param iv The AES Initialization Vector
	 * @param algorithm The algorithm to use (optional and defaults to aes-128-cbc)
	 */
	protected aesEncrypt(
		data: BinaryLike ,
		key: Buffer | string,
		iv: Buffer | string,
		algorithm: Algorithms = "aes-128-cbc") {

		if (typeof key === "string") { key = Buffer.from(key, "base64"); }
		if (typeof iv === "string") { iv = Buffer.from(iv, "base64"); }
		const cipher = crypto.createCipheriv(algorithm, key, iv);
		const encData = cipher.update(data);
		return Buffer.concat([encData, cipher.final()])
			.toString("base64");
	}

	/**
	 * Applies AES Decryption to the base64+AES encrypted data using an AES key and iv
	 * and returns the decrypted data in its original form)
	 * @param enc_data The encrypted data to decrypt
	 * @param is_json Indicates if it was originally a JSON object, if true then it will be returned as JSON
	 * @param key the AES Key
	 * @param iv the AES Initialization Vector
	 * @param algorithm The algorithm to use (optional and defaults to aes-128-cbc)
	 */
	protected aesDecrypt(
		encData: string,
		isJson: boolean = false,
		key: Buffer | string,
		iv: Buffer | string,
		algorithm: Algorithms = "aes-128-cbc") {

		if (typeof key === "string") { key = Buffer.from(key, "base64"); }
		if (typeof iv === "string") { iv = Buffer.from(iv, "base64"); }
		const encDataBuff = Buffer.from(encData, "base64");
		const decipher = crypto.createDecipheriv(algorithm, key, iv);
		const decDataBuff = decipher.update(encDataBuff);
		let decData: string | Buffer = Buffer.concat([decDataBuff, decipher.final()]).toString();
		if (isJson) { decData = JSON.parse(decData) as Buffer; }
		return decData;
	}

	/**
	 * Creates a new AES Key Set
	 * @param algorithm - The algorithm to use (optional and defaults to aes-128-cbc)
	 */
	protected createAESEncryptionKey(algorithm: Algorithms = "aes-128-cbc") {

		let size;
		switch (algorithm) {
			case "aes-128-cbc":
				size = 16; // 16 bytes or 128 bits
				break;
			default:
				throw new Error("Algorithm not supported");
		}
		// generate the new random key and IV which should be of same size
		return { key: crypto.randomBytes(size), iv: crypto.randomBytes(size) };
	}

	/**
	 * Creates a new RSA key pair
	 * @param passphrase - The special passphrase to use the decryption/private key
	 * @param algorithm - The algorithm to use (optional and defaults to aes-128-cbc)
	 * @param modulusLength - The modulus length to use (optional and defaults to 512)
	 */
	protected createRSAEncrytptionKey(
		passphrase: string,
		algorithm: Algorithms = "aes-128-cbc",
		modulusLength: RsaSizes = 512) {

		const keys = generateKeyPairSync("rsa", {
			modulusLength,
			privateKeyEncoding: {
				cipher: algorithm,
				format: "pem",
				passphrase: passphrase.toString(),
				type: "pkcs8",
			},
			publicKeyEncoding: {
				format: "pem",
				type: "spki",
			},
		});
		// just so we do not break our naming convention
		return {
			private_key: keys.privateKey,
			public_key: keys.publicKey,
		};
	}

	/**
	 * Hybrid Decrypts the encrypted data
	 * @param enc_data - The encrypted data to decrypt
	 * @param is_json - Indicates if it was originally a JSON object, if true then it will be returned as JSON
	 * @param rsa_next_pub - the encrypted next message encryption key in the chain that we need to decrypt
	 * @param private_key - the RSA private key used to decrypt the enc_data
	 * @param passphrase - the Passphrase used to generate the RSA private key
	 * @param key - the AES Key (should be byte array, but if its a base64 string, it is cast to a byte array)
	 * @param iv - the AES Initialization Vector
	 * @param algorithm - The algorithm to use (optional and defaults to aes-128-cbc)
	 */
	protected hybridDecrypt(
		body: SwhsBody,
		rsaNextPub: string,
		privateKey: Buffer | string,
		passphrase: string,
		key: Buffer | string,
		iv: Buffer | string,
		algorithm: Algorithms = "aes-128-cbc") {

		try {
			// decrypt the base64 AES key and IV
			if (typeof key === "string") { key = Buffer.from(key, "base64"); }
			key = crypto.privateDecrypt({ key: privateKey, passphrase } , key);
			if (typeof iv === "string") { iv = Buffer.from(iv, "base64"); }
			iv = crypto.privateDecrypt({ key: privateKey, passphrase } , iv);
			const nextPub = this.aesDecrypt(rsaNextPub, false, key, iv);

			let data;
			if (body.enc_body !== undefined || body.enc_body !== "") {
				data = this.aesDecrypt((body.enc_body as string), body.is_json, key, iv);
			}
			return { data, nextPub };
		} catch (err) {
			throw new Error((err as Error).message);
		}
	}

	/**
	 * HybridEncrypts the data
	 * @param data - The data to encrypt
	 * @param rsaPub - The RSA public key to be used to encrypt the data
	 * @param algorithm - The algorithm to use (optional and defaults to aes-128-cbc)
	 * @param modulusLength - The modulus length to use (optional and defaults to 512)
	 */
	protected hybridEncrypt(
		data: BinaryLike | object,
		rsaPub: Buffer | string,
		modulusLength: RsaSizes = 512,
		algorithm: Algorithms = "aes-128-cbc") {
		try {
			let isJson = false;
			if (typeof data === "object") { // cast JSON objects to stringified json
				isJson = true;
				data = JSON.stringify(data);
			}

			// lets create the next RSA public key to use (Double Ratchet)
			const date = new Date();
			const rsaKeys = this.createRSAEncrytptionKey(date.getTime().toString(), algorithm, modulusLength);
			// create a new symetric key set
			const aesSet = this.createAESEncryptionKey(algorithm);
			// encrypt the data and next public key with the AES symetric key
			const encData = this.aesEncrypt(data, aesSet.key, aesSet.iv);
			const nextPub = this.aesEncrypt(rsaKeys.public_key, aesSet.key, aesSet.iv);
			// now encrypt the aes key+iv with the public key and make each base64
			const iv = crypto.publicEncrypt(rsaPub, aesSet.iv).toString("base64");
			const key = crypto.publicEncrypt(rsaPub, aesSet.key).toString("base64");

			return {
				created_date: date.getTime(),
				encData,
				isJson, iv, key, nextPub,
				next_prv: rsaKeys.private_key,
			};
		} catch (err) {
			throw new Error((err as Error).message);
		}
	}
}
