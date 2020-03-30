import crypto, { BinaryLike, generateKeyPairSync } from 'crypto';

const AES_ALGO = 'aes-128-cbc';
const RSA_MODULUS_LENGTH = 512; // this can be made 1024 but it will be slow and bandwidth heavy

/**
* An object containing necessary values used for AES cryptography
*/
export interface AESKeySet {
  key: Buffer;
  iv: Buffer;
}

export interface SwishKeys {
  swishIV: string;
  swishKey: string;
  swishNextPublic: string;
}

export interface SwishHeaders extends SwishKeys{
  swishAction: string;
  swishSessionId: string;
}

export interface SwishBody {
  encBody?: string;
  isJson: boolean;
}

/**
* An object containing the public and private key values used for RSA cryptography
*/
export interface RSAKeySet {
  private: string;
  public: string;
}


/**
* Defines he response object of the hybridEncryption process
*/
export interface HybridEncryptResult {
  createdDate: number;
  body: SwishBody;
  keys: SwishKeys;
  nextPrivate: string;
}

export class HybridCryptography {
  /**
  * Creates an randomized AESKeySet
  */
  createAESEncryptionKey(): AESKeySet {
    const size = 16; // assume 'aes-128-cbc' which is 16byte (16 * 8 = 128bit)
    // generate the new random key and IV which should be of same size
    return { key: crypto.randomBytes(size), iv: crypto.randomBytes(size) };
  }

  /**
   * Applies AES Encryption using an AES key and iv and returns the encrypted data (in base64 form)
   * @param data The data to encrypt
   * @param aes The AES Key Set which contains the key and initialization vector values
   */
  aesEncrypt(
    data: BinaryLike,
    aes: AESKeySet,
  ): string {
    const cipher = crypto.createCipheriv(AES_ALGO, aes.key, aes.iv);
    const encData = cipher.update(data);
    return Buffer.concat([encData, cipher.final()])
      .toString('base64');
  }

  /**
  * Applies AES Decryption to the base64+AES encrypted data using an AES key and iv
  * and returns the decrypted data in its original form)
  * @param encData The encrypted data to unpack
  * @param isJson Indicates if it was originally a JSON object,
  *   if true then it will be returned as JSON
  * @param aes The AES Key Set which contains the key and initialization vector values
  */
  aesDecrypt(
    encData: string,
    isJson = false,
    aes: AESKeySet,
  ): Buffer {
    const encDataBuff = Buffer.from(encData, 'base64');
    const decipher = crypto.createDecipheriv(AES_ALGO, aes.key, aes.iv);
    const decDataBuff = decipher.update(encDataBuff);
    let decData: Buffer = Buffer.concat([decDataBuff, decipher.final()]);
    if (isJson) { decData = JSON.parse(decData.toString()) as Buffer; }
    return decData;
  }

  /**
   * Creates a new RSA key pair
   * @param passphrase - The special passphrase to use the decryption/private key
   */
  protected createRSAEncrytptionKeys(passphrase: string): RSAKeySet {
    const keys = generateKeyPairSync('rsa', {
      modulusLength: RSA_MODULUS_LENGTH,
      privateKeyEncoding: {
        cipher: AES_ALGO,
        format: 'pem',
        passphrase: passphrase.toString(),
        type: 'pkcs8',
      },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });

    return {
      private: keys.privateKey,
      public: keys.publicKey,
    };
  }

  /**
   * Encrypts the data with AES and then encrypts the AES keys with RSA
   * @param data - The data to encrypt. If this is an object, returned 'isJson' will be set to true
   * @param rsaPub - The RSA public key to be used to encrypt the data
   */
  protected hybridEncrypt(
    data: BinaryLike | object,
    rsaPub: string,
  ): HybridEncryptResult {
    const date = new Date();
    const body: SwishBody = { encBody: '', isJson: false };
    let dataString = '';
    if (typeof data === 'object') { // cast JSON objects to stringified json
      body.isJson = true;
      dataString = JSON.stringify(data);
    }

    // lets create the next RSA public key to use (Double Ratchet)
    const rsaKeys = this.createRSAEncrytptionKeys(date.getTime().toString());
    // create a new symetric key set
    const aes = this.createAESEncryptionKey();
    // encrypt the data and next public key with the AES symetric key
    body.encBody = this.aesEncrypt(dataString, aes);
    // now encrypt the aes key+iv with the public key and make each base64
    const keys: SwishKeys = {
      swishKey: crypto.publicEncrypt({ key: rsaPub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, aes.key).toString('base64'),
      swishIV: crypto.publicEncrypt({ key: rsaPub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, aes.iv).toString('base64'),
      swishNextPublic: this.aesEncrypt(rsaKeys.public, aes),
    };

    return {
      createdDate: date.getTime(),
      body,
      keys,
      nextPrivate: rsaKeys.private,
    };
  }

  /**
   * Hybrid Decrypts the encrypted data
   * @param body - The payload to decrypt
   * @param is_json - Indicates if it was originally a JSON object, if true then it will be returned as JSON
   * @param rsa_next_pub - the encrypted next message encryption key in the chain that we need to decrypt
   * @param private_key - the RSA private key used to decrypt the enc_data
   * @param passphrase - the Passphrase used to generate the RSA private key
   * @param key - the AES Key (should be byte array, but if its a base64 string, it is cast to a byte array)
   * @param iv - the AES Initialization Vector
   * @param algorithm - The algorithm to use (optional and defaults to aes-128-cbc)
   */
  protected hybridDecrypt(
    body: SwishBody,
    keys: SwishKeys,
    privateKey: Buffer | string,
    passphrase: string,
  ) {
    // decrypt the base64 AES key and IV
    const key = Buffer.from(keys.swishKey, 'base64');
    const iv = Buffer.from(keys.swishIV, 'base64');
    const aes: AESKeySet = {
      key: crypto.privateDecrypt({ key: privateKey.toString(), passphrase, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, key),
      iv: crypto.privateDecrypt({ key: privateKey.toString(), passphrase, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, iv),
    };
    // now we can retrieve the next public key and current data
    const nextPub = this.aesDecrypt(keys.swishNextPublic, false, aes).toString();

    let data;
    if (body.encBody !== undefined && body.encBody !== '') {
      data = this.aesDecrypt((body.encBody), body.isJson, aes);
    }
    return { data, nextPub };
  }
}
