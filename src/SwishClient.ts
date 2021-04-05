import { BinaryLike } from 'crypto'
import { HybridCryptography, SwishPackage, SwishHeaders } from './HybridCryptography'

export class SwishClient {
  private strSessionId!: string

  private objKeys: {
    nextPublic: string;
    nextPrivate: string;
    createdDate: number;
  }

  /**
   * Gets the current client session id
   */
  public get SessionId(): string {
    return this.strSessionId
  }

  constructor() {
    // set the default
    this.objKeys = { nextPublic: '', nextPrivate: '', createdDate: -1 }
    this.strSessionId = ''
  }

  /**
   * Validates the headers with added keys expected from a server response
   */
  private static validateResponseSwishHeader(headers: SwishHeaders): void {
    if (!headers.swishSessionId) {
      throw new Error('HANDSHAKE_RESPONSE_SESSID_INVALID')
    } else if (!headers.swishAction) {
      throw new Error('HANDSHAKE_RESPONSE_ACTION_INVALID')
    } else if (!headers.swishToken) {
      throw new Error('HANDSHAKE_RESPONSE_TOKEN_INVALID')
    }
    try { // to test is the keys can be retrieved from the token
      HybridCryptography.retrieveKeysFromSwishToken(headers.swishToken)
    } catch {
      throw new Error('HANDSHAKE_RESPONSE_TOKEN_INVALID')
    }
  }

  /**
   * Generates a new handshake request and retrieve the next generated SWISH header values
   */
  public generateHandshake(): SwishPackage {
    // create a new RSA key pair
    const date = new Date()
    const rsa = HybridCryptography.createRSAEncrytptionKeys(date.getTime().toString())
    this.strSessionId = ''
    this.objKeys = {
      createdDate: date.getTime(),
      nextPrivate: rsa.pvtKey,
      nextPublic: rsa.pubKey,
    }

    // create a new aes set to encrypt the 'response public key'
    const aes = HybridCryptography.createAESEncryptionKey()
    const encNextPub = HybridCryptography.aesEncrypt(
      this.objKeys.nextPublic,
      aes,
    )
    const swishToken = HybridCryptography.createSwishToken(aes.iv.toString('base64'), aes.key.toString('base64'), encNextPub)
    return {
      body: {
        encBody: '',
        isJson: false,
      },
      headers: {
        swishAction: 'handshake_init',
        swishToken,
        swishSessionId: '',
      },
    }
  }

  /**
   * Encrypts a request body and retrieve the next generated SWISH header values
   * @param body - The request body to encrypt
   */
  public encryptRequest(body: BinaryLike | Record<string, unknown>): SwishPackage {
    if (!body) {
      throw new Error('HYBRIDCRYPTO_REQUEST_BODY_INVALID')
    } else if (!this.objKeys.nextPublic) {
      throw new Error('HYBRIDCRYPTO_CLIENT_NEXTPUB_NOT_SET')
    }

    const result = HybridCryptography.hybridEncrypt(body, this.objKeys.nextPublic)
    this.objKeys.nextPrivate = result.nextPrivate
    this.objKeys.createdDate = result.createdDate

    const swishToken = HybridCryptography.createSwishToken(result.keys.aesIV, result.keys.aesKey, result.keys.rsaNextPublic)
    return {
      body: result.body,
      headers: {
        swishAction: 'request_basic',
        swishToken,
        swishSessionId: this.strSessionId,
      },
    }
  }

  /**
   * Handle the response from the SWISH service and stores the next pub key in the chain
   * @param options - The swish object containing the swish headers and body
   */
  public handleHandshakeResponse(options: SwishPackage): Buffer | Record<string, unknown> {
    // if new session id, assign it
    if (options.headers.swishSessionId && this.strSessionId !== options.headers.swishSessionId) {
      this.strSessionId = options.headers.swishSessionId
    }
    // retrieve the next request sequenced pub key
    return this.decryptResponse(options)
  }

  /**
   * Decrypt the encrypted response and stores the next pub key in the chain
   * @param options - The swish object containing the swish headers and body
   */
  public decryptResponse(options: SwishPackage): Buffer | Record<string, unknown> {
    SwishClient.validateResponseSwishHeader(options.headers)
    const swishKeys = HybridCryptography.retrieveKeysFromSwishToken(options.headers.swishToken)
    const decrypted = HybridCryptography.hybridDecrypt(
      options.body,
      swishKeys,
      this.objKeys.nextPrivate,
      this.objKeys.createdDate.toString(),
    )

    // set the next request public key in memory and return the body
    this.objKeys.nextPublic = decrypted.nextPublic
    return decrypted.data
  }
}
