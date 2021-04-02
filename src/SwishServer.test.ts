import { SwishServer } from './SwishServer';
import { SwishHeaders, HybridCryptography } from './HybridCryptography';

// prepare the keys for testing
const passphrase = 'hakunamatata';
const server = new SwishServer();
const crypt = new HybridCryptography();
const { key, iv } = crypt.createAESEncryptionKey();
const { pvtKey, pubKey } = crypt.createRSAEncrytptionKeys(passphrase);
const nextPubkey = crypt.aesEncrypt(pubKey, { key, iv });

describe('SwishServer.handleHandshakeRequest', () => {
  const headers: SwishHeaders = {
    swishAction: '',
    swishIV: '',
    swishKey: '',
    swishNextPublic: '',
    swishSessionId: '',
  };

  test('should ensure there is a sessionId value to associate the session with', () => {
    try {
      server.handleHandshakeRequest(headers);
    } catch (err) {
      expect((err as Error).message).toMatch('SESSION_ID_INVALID');
    }
  });

  test('should ensure the swishAction value is handshake_init', () => {
    try {
      headers.swishSessionId = 'adonisv79';
      headers.swishAction = 'something_else';
      server.handleHandshakeRequest(headers);
    } catch (err) {
      expect((err as Error).message).toMatch('HANDSHAKE_INVALID_INIT');
    }
  });

  test('should ensure the swishKey is valid', () => {
    try {
      headers.swishSessionId = 'adonisv79';
      headers.swishAction = 'handshake_init';
      server.handleHandshakeRequest(headers);
    } catch (err) {
      expect((err as Error).message).toMatch('HANDSHAKE_KEY_INVALID');
    }
  });

  test('should ensure the swishKey is valid', () => {
    try {
      headers.swishSessionId = 'adonisv79';
      headers.swishAction = 'handshake_init';
      server.handleHandshakeRequest(headers);
    } catch (err) {
      expect((err as Error).message).toMatch('HANDSHAKE_KEY_INVALID');
    }
  });

  test('should ensure the swishIV is valid', () => {
    try {
      headers.swishSessionId = 'adonisv79';
      headers.swishAction = 'handshake_init';
      headers.swishKey = key.toString('base64');
      server.handleHandshakeRequest(headers);
    } catch (err) {
      expect((err as Error).message).toMatch('HANDSHAKE_AES_IV_INVALID');
    }
  });

  test('should ensure the swishNextPublic is valid for decryption using the key and iv', () => {
    try {
      headers.swishSessionId = 'adonisv79';
      headers.swishAction = 'handshake_init';
      headers.swishKey = key.toString('base64');
      headers.swishIV = iv.toString('base64');
      server.handleHandshakeRequest(headers);
    } catch (err) {
      expect((err as Error).message).toMatch('HANDSHAKE_NEXTPUBKEY_DECRYPT_FAILED');
    }
  });

  test('should respond the new randomized key sets based submitted request', () => {
    headers.swishSessionId = 'adonisv79';
    headers.swishAction = 'handshake_init';
    headers.swishKey = key.toString('base64');
    headers.swishIV = iv.toString('base64');
    headers.swishNextPublic = nextPubkey;
    const result = server.handleHandshakeRequest(headers);
    expect(result.headers.swishSessionId).toBe(headers.swishSessionId);
    expect(result.headers.swishAction).toBe('handshake_response');
    expect(result.headers.swishIV).toBeTruthy();
    expect(result.headers.swishKey).toBeTruthy();
    expect(result.headers.swishNextPublic).toBeTruthy();
    // try to decrypt the data and analyze its content
    expect(result.body.encBody).toBeTruthy();
    const bodyDec = crypt.hybridDecrypt(
      result.body,
      {
        swishIV: result.headers.swishIV,
        swishKey: result.headers.swishKey,
        swishNextPublic: result.headers.swishNextPublic,
      }, pvtKey, passphrase,
    );
    expect(bodyDec.data).toStrictEqual({ status: 'ok' });
    expect(bodyDec.nextPublic).toBeTruthy();
  });
});

describe('SwishServer.decryptRequest', () => {
  const headers: SwishHeaders = {
    swishSessionId: 'adonisv79',
    swishAction: 'handshake_init',
    swishIV: '',
    swishKey: '',
    swishNextPublic: '',
  };
  let encBody: string;
  let nextServerPrivate: string;
  let serverKeyCreatedDate: number;

  beforeEach(() => {
    // we need to create a handshake and retrieve the next decryption mechanism of the server
    const handshakeResult = server.handleHandshakeRequest({
      swishSessionId: 'adonisv79',
      swishAction: 'handshake_init',
      swishIV: iv.toString('base64'),
      swishKey: key.toString('base64'),
      swishNextPublic: nextPubkey,
    });
    nextServerPrivate = handshakeResult.decrypt.nextPrivate;
    serverKeyCreatedDate = handshakeResult.decrypt.createdDate;

    const hDecResult = crypt.hybridDecrypt(
      handshakeResult.body,
      {
        swishKey: handshakeResult.headers.swishKey,
        swishIV: handshakeResult.headers.swishIV,
        swishNextPublic: handshakeResult.headers.swishNextPublic,
      }, pvtKey, passphrase,
    );

    const newRequest = crypt.hybridEncrypt({ foo: 'bar', score: 100 }, hDecResult.nextPublic);
    headers.swishKey = newRequest.keys.swishKey;
    headers.swishIV = newRequest.keys.swishIV;
    headers.swishNextPublic = newRequest.keys.swishNextPublic;
    encBody = newRequest.body.encBody;
  });

  test('should throw [HYBRIDCRYPT_ARGS_CLIENTKEYS_INVALID] if any of the client provided keys are invalid', () => {
    expect(() => {
      server.decryptRequest(
        {
          swishIV: '',
          swishKey: '',
          swishNextPublic: '',
          swishAction: '',
          swishSessionId: '',
        },
        { encBody, isJson: true },
        nextServerPrivate,
        serverKeyCreatedDate.toString(),
      );
    }).toThrow('HYBRIDCRYPT_ARGS_CLIENTKEYS_INVALID');
  });

  test('should throw [HYBRIDCRYPT_ARGS_BODY_INVALID] if server encrypted body is invalid', () => {
    expect(() => {
      server.decryptRequest(
        headers,
        { encBody: '', isJson: true },
        nextServerPrivate,
        serverKeyCreatedDate.toString(),
      );
    }).toThrow('HYBRIDCRYPT_ARGS_BODY_INVALID');
  });

  test('should throw [HYBRIDCRYPT_ARGS_PVTKEY_INVALID] if server private key is invalid', () => {
    expect(() => {
      server.decryptRequest(
        headers,
        { encBody, isJson: true },
        '',
        serverKeyCreatedDate.toString(),
      );
    }).toThrow('HYBRIDCRYPT_ARGS_PVTKEY_INVALID');
  });

  test('should throw an error when you pass an empty passphrase', () => {
    expect(() => {
      server.decryptRequest(
        headers,
        { encBody, isJson: true },
        nextServerPrivate,
        '',
      );
    }).toThrow('HYBRIDCRYPT_ARGS_PASSPHRASE_INVALID');
  });

  test('should throw an error when you pass a wrong passphrase', () => {
    expect(() => {
      server.decryptRequest(
        headers,
        { encBody, isJson: true },
        nextServerPrivate,
        'wrong passphrase',
      );
    }).toThrowError();
  });

  test('should throw [HYBRIDCRYPT_HDEC_AESKEY_FAILED] when you pass a wrong key', () => {
    expect(() => {
      server.decryptRequest(
        {
          swishSessionId: headers.swishSessionId,
          swishAction: headers.swishAction,
          swishKey: 'this should break',
          swishIV: headers.swishIV,
          swishNextPublic: headers.swishNextPublic,
        },
        { encBody, isJson: true },
        nextServerPrivate,
        serverKeyCreatedDate.toString(),
      );
    }).toThrow('HYBRIDCRYPT_HDEC_AESKEY_FAILED');
  });

  test('should throw [HYBRIDCRYPT_HDEC_AESIV_FAILED] when you pass a wrong iv', () => {
    expect(() => {
      server.decryptRequest(
        {
          swishSessionId: headers.swishSessionId,
          swishAction: headers.swishAction,
          swishKey: headers.swishKey,
          swishIV: 'this should break',
          swishNextPublic: headers.swishNextPublic,
        },
        { encBody, isJson: true },
        nextServerPrivate,
        serverKeyCreatedDate.toString(),
      );
    }).toThrow('HYBRIDCRYPT_HDEC_AESIV_FAILED');
  });

  test('should throw [HYBRIDCRYPT_HDEC_BODY_FAILED] when you pass the wrong body (not decryptable by given keys)', () => {
    expect(() => {
      server.decryptRequest(
        {
          swishSessionId: headers.swishSessionId,
          swishAction: headers.swishAction,
          swishKey: headers.swishKey,
          swishIV: headers.swishIV,
          swishNextPublic: headers.swishNextPublic,
        },
        { encBody: 'this should break', isJson: true },
        nextServerPrivate,
        serverKeyCreatedDate.toString(),
      );
    }).toThrow('HYBRIDCRYPT_HDEC_BODY_FAILED');
  });

  test('should throw [HYBRIDCRYPT_HDEC_NEXTPUB_FAILED] when you pass a wrong next pub key', () => {
    expect(() => {
      server.decryptRequest(
        {
          swishSessionId: headers.swishSessionId,
          swishAction: headers.swishAction,
          swishKey: headers.swishKey,
          swishIV: headers.swishIV,
          swishNextPublic: 'this should break',
        },
        { encBody, isJson: true },
        nextServerPrivate,
        serverKeyCreatedDate.toString(),
      );
    }).toThrow('HYBRIDCRYPT_HDEC_NEXTPUB_FAILED');
  });

  test('should successfully retrieve the request body but return buffered string value isJson set to false', () => {
    const decResponse = server.decryptRequest(
      headers,
      { encBody, isJson: false },
      nextServerPrivate,
      serverKeyCreatedDate.toString(),
    );
    expect(decResponse.body).toStrictEqual(Buffer.from(JSON.stringify({ foo: 'bar', score: 100 })));
    expect(decResponse.nextPubKey).toBeTruthy();
  });

  test('should successfully retrieve the request body and generate the next pub key', () => {
    const decResponse = server.decryptRequest(
      headers,
      { encBody, isJson: true },
      nextServerPrivate,
      serverKeyCreatedDate.toString(),
    );
    expect(decResponse.body).toStrictEqual({ foo: 'bar', score: 100 });
    expect(decResponse.nextPubKey).toBeTruthy();
  });
});

describe('SwishServer.encryptResponse', () => {
  test('should throw [PUBLIC_KEY_INVALID] if provided public key is invalid', () => {
    expect(() => {
      server.encryptResponse('adonisv79', { foo: 'bar' }, '');
    }).toThrow('PUBLIC_KEY_INVALID');
  });

  test('should throw [BODY_INVALID] if provided response body is falsey', () => {
    expect(() => {
      server.encryptResponse('adonisv79', '', pubKey);
    }).toThrow('BODY_INVALID');
  });

  test('should return the complete encrypted response with decryption keys', () => {
    const encData = server.encryptResponse('adonisv79', { foo: 'bar' }, pubKey);
    expect(encData.body).toBeTruthy();
    expect(encData.body.encBody).toBeTruthy();
    expect(encData.body.isJson).toBeTruthy();
    expect(encData.body).toBeTruthy();
    expect(encData.decrypt).toBeTruthy();
    expect(encData.decrypt.createdDate).toBeTruthy();
    expect(encData.decrypt.nextPrivate).toBeTruthy();
    expect(encData.headers).toBeTruthy();
    expect(encData.headers.swishSessionId).toEqual('adonisv79');
    expect(encData.headers.swishAction).toEqual('encrypt_response');
    expect(encData.headers.swishIV).toBeTruthy();
    expect(encData.headers.swishKey).toBeTruthy();
    expect(encData.headers.swishNextPublic).toBeTruthy();
  });
});
