import { BinaryLike } from 'crypto';
import { HybridCryptography, SwishPackage, SwishHeaders } from './HybridCryptography';

export class SwishClient extends HybridCryptography {
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
  private validateResponseSwishHeader(headers: SwishHeaders): void {
    if (!headers.swishSessionId) {
      throw new Error('HANDSHAKE_INVALID: Missing from header Swish Session Id');
    } else if (this.strSessionId && this.strSessionId !== headers.swishSessionId) {
      throw new Error('HANDSHAKE_INVALID: Session ID mismatch');
    }
  }

  /**
   * Generates a new handshake request and retrieve the next generated SWISH header values
   */
  public generateHandshake(): SwishPackage {
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
   * @param body - The request body to encrypt
   */
  public encryptRequest(body: BinaryLike | object): SwishPackage {
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
   * @param options - The swish object containing the swish headers and body
   */
  public handleHandshakeResponse(options: SwishPackage): Buffer {
    // if new session id, assign it
    if (!this.strSessionId && options.headers.swishSessionId) {
      this.strSessionId = options.headers.swishSessionId;
    }
    // retrieve the next request sequenced pub key
    return this.decryptResponse(options);
  }

  /**
   * Decrypt the encrypted response and stores the next pub key in the chain
   * @param options - The swish object containing the swish headers and body
   */
  public decryptResponse(options: SwishPackage): Buffer {
    this.validateResponseSwishHeader(options.headers);
    const decrypted = this.hybridDecrypt(
      options.body,
      options.headers,
      this.objKeys.nextPrivate,
      this.objKeys.createdDate.toString(),
    );

    // set the next request public key in memory and return the body
    this.objKeys.nextPublic = decrypted.nextPublic;
    return decrypted.data;
  }
}
