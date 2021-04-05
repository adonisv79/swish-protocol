import { BinaryLike } from 'crypto'

import {
  HybridCryptography,
  SwishBody,
  SwishHeaders,
} from './HybridCryptography'

/** The Decryption private key response */
export interface SwishDecryption {
  nextPrivate: string;
  createdDate: number;
}

export interface DecryptedRequest {
  body: Buffer | Record<string, unknown>;
  nextPubKey: string;
}

export interface EncryptedResponse {
  headers: SwishHeaders;
  body: SwishBody;
  decrypt: SwishDecryption;
}

export class SwishServer extends HybridCryptography {
  /**
   * Handles a handshake request from a new client
   * @param headers - The request headers
   */
  public static handleHandshakeRequest(headers: SwishHeaders): EncryptedResponse {
    if (headers.swishSessionId === '') {
      throw new Error('SESSION_ID_INVALID')
    } else if (headers.swishAction !== 'handshake_init') {
      throw new Error('HANDSHAKE_INVALID_INIT')
    }

    const swishKeys = HybridCryptography.retrieveKeysFromSwishToken(headers.swishToken)
    const iv = Buffer.from(swishKeys.aesIV, 'base64')
    const key = Buffer.from(swishKeys.aesKey, 'base64')

    let responsePubKey: string
    // first lets decrypt that public key for sending our responses to this client
    try {
      responsePubKey = HybridCryptography.aesDecrypt(
        swishKeys.rsaNextPublic, false, { key, iv },
      ).toString()
    } catch (err) {
      throw new Error('HANDSHAKE_NEXTPUBKEY_DECRYPT_FAILED')
    }

    // encrypt an ok response using the client's response public key
    const result = SwishServer.encryptResponse(headers.swishSessionId, { status: 'ok' }, responsePubKey)
    result.headers.swishAction = 'handshake_response' // override the action value
    return result
  }

  /**
   * Decrypt the encrypted request with the session's next request decrypt key
   * @param headers - The request headers
   * @param body - The request body
   * @param nextPrivate - The next RSA private key used to decrypt the body
   * @param passphrase - The Passphrase used to generate the RSA private key
   */
  public static decryptRequest(
    headers: SwishHeaders,
    body: SwishBody,
    nextPrivate: string,
    passphrase: string,
  ): DecryptedRequest {
    const swishKeys = HybridCryptography.retrieveKeysFromSwishToken(headers.swishToken)
    const decrypted = HybridCryptography.hybridDecrypt(
      body,
      swishKeys,
      nextPrivate,
      passphrase,
    )

    return {
      body: decrypted.data,
      nextPubKey: decrypted.nextPublic,
    }
  }

  /**
   * Encrypt the response with the session public key
   * @param swishSessionId - The unique session identifier
   * @param body - The response body to encrypt
   * @param nextPublic - The next RSA Public key in the chain to encrypt the body
   */
  public static encryptResponse(
    swishSessionId: string,
    body: BinaryLike | Record<string, unknown>,
    nextPublic: string,
  ): EncryptedResponse {
    if (!nextPublic) {
      throw new Error('PUBLIC_KEY_INVALID')
    } else if (!body) {
      throw new Error('BODY_INVALID')
    }

    // use Hybrid Encryption and return the response in the proper structure
    const result = HybridCryptography.hybridEncrypt(body, nextPublic)
    return {
      body: result.body,
      decrypt: {
        createdDate: result.createdDate,
        nextPrivate: result.nextPrivate,
      },
      headers: {
        swishAction: 'encrypt_response',
        swishToken: `${result.keys.aesIV}.${result.keys.aesKey}.${result.keys.rsaNextPublic}`,
        swishSessionId,
      },
    }
  }
}
