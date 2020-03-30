import { BinaryLike } from 'crypto';

import {
  HybridCryptography,
  SwishBody,
  SwishHeaders,
  AESKeySet,
} from './HybridCryptography';

export interface SwishDecryption {
  nextPrivate: string;
  createdDate: number;
}

export class HandshakeServer extends HybridCryptography {
  /**
   * Handles a handshake request from a new client
   * @param headers - the request headers
   * @param sessionId - the unique session identifier
   */
  public handleHandshakeRequest(headers: SwishHeaders) {
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
   * @param headers - the request headers
   * @param req_body - the request body
   * @param next_prv - the RSA private key used to decrypt the req_body
   * @param passphrase - the Passphrase used to generate the RSA private key
   */
  public decryptRequest(
    headers: SwishHeaders,
    body: SwishBody,
    nextPrv: Buffer,
    passphrase: string,
  ) {
    const decrypted = this.hybridDecrypt(
      body,
      headers,
      nextPrv,
      passphrase,
    );

    return {
      body: decrypted.data as any,
      nextPubKey: decrypted.nextPub,
    };
  }

  /**
   * Encrypt the response with the session public key
   * @param swishSessionId - the unique session identifier
   * @param body - the response body to encrypt
   */
  public encryptResponse(
    swishSessionId: string,
    body: BinaryLike | object,
    rsaPub: string,
  ): { headers: SwishHeaders; body: SwishBody; decrypt: SwishDecryption } {
    if (!rsaPub) {
      throw new Error('PUBLIC_KEY_INVALID');
    } else if (!body) {
      throw new Error('BODY_INVALID');
    }

    // use Hybrid Encryption and return the response in the proper structure
    const result = this.hybridEncrypt(body, rsaPub);
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
