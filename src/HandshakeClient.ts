import { BinaryLike } from 'crypto';

import { HybridCryptography, SwishBody, SwishHeaders } from './HybridCryptography';

export class HandshakeClient extends HybridCryptography {
  private strSessionId!: string;

  private objKeys: {
    nextPublic: string;
    nextPrivate: string;
    createdDate: number;
  };

  /**
   * Gets the current client session id
   */
  public get SessionId(): string {
    return this.strSessionId;
  }

  constructor() {
    super();
    // set the default
    this.objKeys = { nextPublic: '', nextPrivate: '', createdDate: -1 };
    this.strSessionId = '';
  }

  /**
   * Validates the headers with added keys expected from a server response
   */
  public validateResponseSwishHeader(headers: SwishHeaders): void {
    if (!headers.swishSessionId) {
      throw new Error('HANDSHAKE_INVALID: Missing from header Swish Session Id');
    } else if (this.strSessionId && this.strSessionId !== headers.swishSessionId) {
      throw new Error('HANDSHAKE_INVALID: Session ID mismatch');
    }
  }

  /**
   * Generates a new handshake request and retrieve the next generated SWISH header values
   */
  public generateHandshake(): { headers: SwishHeaders; body: SwishBody} {
    // create a new RSA key pair
    const date = new Date();
    const rsa = this.createRSAEncrytptionKeys(date.getTime().toString());
    this.strSessionId = '';
    this.objKeys = {
      createdDate: date.getTime(),
      nextPrivate: rsa.private,
      nextPublic: rsa.public,
    };

    // create a new aes set to encrypt the 'response public key'
    const aes = this.createAESEncryptionKey();
    const encNextPub = this.aesEncrypt(
      this.objKeys.nextPublic,
      aes,
    );
    return {
      body: {
        encBody: '',
        isJson: false,
      },
      headers: {
        swishAction: 'handshake_init',
        swishIV: aes.iv.toString('base64'),
        swishKey: aes.key.toString('base64'),
        swishNextPublic: encNextPub,
        swishSessionId: '',
      },
    };
  }

  /**
   * Encrypts a request body and retrieve the next generated SWISH header values
   * @param body - the request body to encrypt
   */
  public encryptRequest(body: BinaryLike | object): { headers: SwishHeaders; body: SwishBody } {
    if (!body) {
      throw new Error('BODY_INVALID');
    } else if (!this.objKeys.nextPublic) {
      throw new Error('Next public request key is not set!');
    }

    const result = this.hybridEncrypt(body, this.objKeys.nextPublic);
    this.objKeys.nextPrivate = result.nextPrivate;
    this.objKeys.createdDate = result.createdDate;

    return {
      body: result.body,
      headers: {
        swishAction: 'request_basic',
        swishIV: result.keys.swishIV,
        swishKey: result.keys.swishKey,
        swishNextPublic: result.keys.swishNextPublic,
        swishSessionId: this.strSessionId,
      },
    };
  }

  /**
   * Handle the response from the SWISH service and stores the next pub key in the chain
   * @param headers - The response headers
   * @param body - The response body
   */
  public handleHandshakeResponse(headers: SwishHeaders, body: SwishBody) {
    // if new session id, assign it
    if (!this.strSessionId && headers.swishSessionId) {
      this.strSessionId = headers.swishSessionId;
    }
    // retrieve the next request sequenced pub key
    return this.decryptResponse(headers, body);
  }

  /**
   * Decrypt the encrypted response and stores the next pub key in the chain
   * @param headers - The response headers
   * @param body - The response body
   */
  public decryptResponse(headers: SwishHeaders, body: SwishBody) {
    this.validateResponseSwishHeader(headers);
    const decrypted = this.hybridDecrypt(
      body,
      headers,
      this.objKeys.nextPrivate,
      this.objKeys.createdDate.toString(),
    );

    // set the next request public key in memory and return the body
    this.objKeys.nextPublic = decrypted.nextPublic;
    return decrypted.data;
  }
}
