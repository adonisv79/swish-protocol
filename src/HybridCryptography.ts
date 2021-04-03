import crypto, { BinaryLike, generateKeyPairSync } from 'crypto'

const AES_ALGO = 'aes-128-cbc'
const RSA_MODULUS_LENGTH = 512 // this can be made 1024 but it will be slow and bandwidth heavy

/** An object containing necessary values used for AES cryptography */
export interface AESKeySet {
  /** The AES Key */
  key: Buffer;
  /** The AES Initialization Vector */
  iv: Buffer;
}

/** An object containing the public and private key values used for RSA cryptography */
export interface RSAKeySet {
  /** The private key held only by the client or server */
  pvtKey: string;
  /** The public key which is freely passed between client and server */
  pubKey: string;
}

/** Defines the basic keys found on the SwishHeader */
export interface SwishKeys {
  /** The AES Initialization Vector */
  swishIV: string;
  /** The AES Key */
  swishKey: string;
  /** The next public key to be used in the transaction chain */
  swishNextPublic: string;
}

/** Defines a complete header object and all its required members */
export interface SwishHeaders extends SwishKeys{
  /** The swish action to implement */
  swishAction: string;
  /** The unique user session identifier */
  swishSessionId: string;
}

/** The encrypted message and its metadata */
export interface SwishBody {
  /** The encrypted data in Base64 string format */
  encBody: string;
  /** Defines if the encrypted data is a JSON and should be parsed back to an object automaticaly */
  isJson: boolean;
}

/** Defines an ancapsulated object containing the swish header and body */
export interface SwishPackage {
  /** The Swish request header data */
  headers: SwishHeaders;
  /** The Swish request body data */
  body: SwishBody;
}

/**
* Defines the response object of the hybrid encryption process
*/
export interface HybridEncryptResult {
  createdDate: number;
  body: SwishBody;
  keys: SwishKeys;
  nextPrivate: string;
}

/**
* Defines the response object of the hybrid decryption process
*/
export interface HybridDecryptResult {
  data: Buffer;
  nextPublic: string;
}

export class HybridCryptography {
  /**
  * Creates an randomized AESKeySet
  */
  static createAESEncryptionKey(): AESKeySet {
    const size = 16 // assume 'aes-128-cbc' which is 16byte (16 * 8 = 128bit)
    // generate the new random key and IV which should be of same size
    return { key: crypto.randomBytes(size), iv: crypto.randomBytes(size) }
  }

  /**
   * Applies AES Encryption using an AES key and iv and returns the encrypted data (in base64 form)
   * @param data The data to encrypt
   * @param aes The AES Key Set which contains the key and initialization vector values
   */
  static aesEncrypt(
    data: BinaryLike,
    aes: AESKeySet,
  ): string {
    try {
      const cipher = crypto.createCipheriv(AES_ALGO, aes.key, aes.iv)
      const encData = cipher.update(data)
      return Buffer.concat([encData, cipher.final()])
        .toString('base64')
    } catch {
      throw new Error('HYBRIDCRYPTO_AES_ENCRYPTION_FAILED')
    }
  }

  /**
  * Applies AES Decryption to the base64+AES encrypted data using an AES key and iv
  * and returns the decrypted data in its original form)
  * @param encData The encrypted data to unpack
  * @param isJson Indicates if it was originally a JSON object,
  *   if true then it will be returned as JSON
  * @param aes The AES Key Set which contains the key and initialization vector values
  */
  static aesDecrypt(
    encData: string,
    isJson = false,
    aes: AESKeySet,
  ): Buffer {
    try {
      const encDataBuff = Buffer.from(encData, 'base64')
      const decipher = crypto.createDecipheriv(AES_ALGO, aes.key, aes.iv)
      const decDataBuff = decipher.update(encDataBuff)
      let decData: Buffer = Buffer.concat([decDataBuff, decipher.final()])
      if (isJson) { decData = JSON.parse(decData.toString()) as Buffer }
      return decData
    } catch {
      throw new Error('HYBRIDCRYPTO_AES_DECRYPTION_FAILED')
    }
  }

  /**
   * Creates a new RSA key pair
   * @param passphrase - The special passphrase to use the decryption/private key
   */
  static createRSAEncrytptionKeys(passphrase: string): RSAKeySet {
    const keys = generateKeyPairSync('rsa', {
      modulusLength: RSA_MODULUS_LENGTH,
      privateKeyEncoding: {
        cipher: AES_ALGO,
        format: 'pem',
        passphrase: passphrase.toString(),
        type: 'pkcs8',
      },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    })

    return {
      pvtKey: keys.privateKey,
      pubKey: keys.publicKey,
    }
  }

  /**
   * Encrypts the data with AES and then encrypts the AES keys with RSA
   * @param data - The data to encrypt. If this is an object, returned 'isJson' will be set to true
   * @param rsaPub - The RSA public key to be used to encrypt the data
   */
  static hybridEncrypt(
    data: BinaryLike | Record<string, unknown>,
    rsaPub: string,
  ): HybridEncryptResult {
    const date = new Date()
    const body: SwishBody = { encBody: '', isJson: false }
    let dataString = ''
    if (typeof data === 'object') { // cast JSON objects to stringified json
      body.isJson = true
      dataString = JSON.stringify(data)
    }

    // lets create the next RSA public key to use (Double Ratchet)
    const rsaKeys = HybridCryptography.createRSAEncrytptionKeys(date.getTime().toString())
    // create a new symetric key set
    const aes = HybridCryptography.createAESEncryptionKey()
    // encrypt the data and next public key with the AES symetric key
    body.encBody = HybridCryptography.aesEncrypt(dataString, aes)
    // now encrypt the aes key+iv with the public key and make each base64
    const keys: SwishKeys = {
      swishKey: crypto.publicEncrypt({ key: rsaPub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, aes.key).toString('base64'),
      swishIV: crypto.publicEncrypt({ key: rsaPub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, aes.iv).toString('base64'),
      swishNextPublic: HybridCryptography.aesEncrypt(rsaKeys.pubKey, aes),
    }

    return {
      createdDate: date.getTime(),
      body,
      keys,
      nextPrivate: rsaKeys.pvtKey,
    }
  }

  /**
   * Decrypts the hybrid encrypted data
   * @param body - The payload to decrypt
   * @param keys - The SwishKeys that contain information on how to decrypt the data and the next public in the chain
   * @param privateKey - the next private key for decryption in the chain
   * @param passphrase - the Passphrase used to generate the RSA private key
   */
  static hybridDecrypt(
    body: SwishBody,
    keys: SwishKeys,
    privateKey: string,
    passphrase: string,
  ): HybridDecryptResult {
    // decrypt the base64 AES key and IV
    if (!body || !body.encBody) { throw new Error('HYBRIDCRYPT_ARGS_BODY_INVALID') }
    if (!keys || !keys.swishIV || !keys.swishKey || !keys.swishNextPublic) { throw new Error('HYBRIDCRYPT_ARGS_CLIENTKEYS_INVALID') }
    if (!privateKey) { throw new Error('HYBRIDCRYPT_ARGS_PVTKEY_INVALID') }
    if (!passphrase) { throw new Error('HYBRIDCRYPT_ARGS_PASSPHRASE_INVALID') }

    let key: Buffer
    try {
      key = Buffer.from(keys.swishKey, 'base64')
      key = crypto.privateDecrypt({ key: privateKey, passphrase, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, key)
    } catch (err) {
      throw new Error('HYBRIDCRYPT_HDEC_AESKEY_FAILED')
    }

    let iv: Buffer
    try {
      iv = Buffer.from(keys.swishIV, 'base64')
      iv = crypto.privateDecrypt({ key: privateKey, passphrase, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, iv)
    } catch (err) {
      throw new Error('HYBRIDCRYPT_HDEC_AESIV_FAILED')
    }

    let data: Buffer
    try {
      data = HybridCryptography.aesDecrypt((body.encBody), body.isJson, { key, iv })
    } catch (err) {
      throw new Error('HYBRIDCRYPT_HDEC_BODY_FAILED')
    }

    let nextPublic: string
    try {
      nextPublic = HybridCryptography.aesDecrypt(keys.swishNextPublic, false, { key, iv }).toString()
    } catch (err) {
      throw new Error('HYBRIDCRYPT_HDEC_NEXTPUB_FAILED')
    }

    return { data, nextPublic }
  }
}
