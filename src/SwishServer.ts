import { BinaryLike } from 'crypto';

import {
  HybridCryptography,
  SwishBody,
  SwishHeaders,
  AESKeySet,
} from './HybridCryptography';

/** The Decryption private key response */
export interface SwishDecryption {
  nextPrivate: string;
  createdDate: number;
}

export class SwishServer extends HybridCryptography {
  /**
   * Handles a handshake request from a new client
   * @param headers - The request headers
   */
  public handleHandshakeRequest(headers: SwishHeaders): { headers: SwishHeaders; body: SwishBody; decrypt: SwishDecryption } {
    if (headers.swishSessionId === '') {
      throw new Error('SESSION_ID_INVALID');
    } else if (headers.swishAction !== 'handshake_init') {
      throw new Error('HANDSHAKE_INVALID_INIT');
    } else if (headers.swishIV.length < 10) {
      throw new Error('HANDSHAKE_AES_IV_INVALID');
    }

    const aes: AESKeySet = {
      key: Buffer.from(headers.swishKey, 'base64'),
      iv: Buffer.from(headers.swishIV, 'base64'),
    };

    // first lets decrypt that public key for sending our responses to this client
    const responsePubKey = this.aesDecrypt(
      headers.swishNextPublic, false, aes,
    ).toString();

    // encrypt an ok response using the client's response public key
    const result = this.encryptResponse(headers.swishSessionId, { status: 'ok' }, responsePubKey);

    result.headers.swishAction = 'handshake_response'; // override the action value
    return result;
  }

  /**
   * Decrypt the encrypted request with the session's next request decrypt key
   * @param headers - The request headers
   * @param body - The request body
   * @param nextPrivate - The next RSA private key used to decrypt the body
   * @param passphrase - The Passphrase used to generate the RSA private key
   */
  public decryptRequest(
    headers: SwishHeaders,
    body: SwishBody,
    nextPrivate: string,
    passphrase: string,
  ): { body: Buffer; nextPubKey: string } {
    const decrypted = this.hybridDecrypt(
      body,
      headers,
      nextPrivate,
      passphrase,
    );

    return {
      body: decrypted.data,
      nextPubKey: decrypted.nextPublic,
    };
  }

  /**
   * Encrypt the response with the session public key
   * @param swishSessionId - The unique session identifier
   * @param body - The response body to encrypt
   * @param nextPublic - The next RSA Public key in the chain to encrypt the body
   */
  public encryptResponse(
    swishSessionId: string,
    body: BinaryLike | object,
    nextPublic: string,
  ): { headers: SwishHeaders; body: SwishBody; decrypt: SwishDecryption } {
    if (!nextPublic) {
      throw new Error('PUBLIC_KEY_INVALID');
    } else if (!body) {
      throw new Error('BODY_INVALID');
    }

    // use Hybrid Encryption and return the response in the proper structure
    const result = this.hybridEncrypt(body, nextPublic);
    return {
      body: result.body,
      decrypt: {
        createdDate: result.createdDate,
        nextPrivate: result.nextPrivate,
      },
      headers: {
        swishAction: 'encrypt_response',
        swishIV: result.keys.swishIV,
        swishKey: result.keys.swishKey,
        swishNextPublic: result.keys.swishNextPublic,
        swishSessionId,
      },
    };
  }
}
