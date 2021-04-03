import { SwishClient } from './SwishClient'
import { SwishServer } from './SwishServer'

import { HybridCryptography } from './HybridCryptography'

const passphrase = 'hakunamatata'
const client = new SwishClient()
const { key, iv } = HybridCryptography.createAESEncryptionKey()
const { pubKey } = HybridCryptography.createRSAEncrytptionKeys(passphrase)

describe('SwishClient.generateHandshake', () => {
  test('should be able to generate a new handshake', () => {
    const handShake = client.generateHandshake()
    expect(client.SessionId).toEqual('') // this is empty during start of handshake
    expect(handShake.body).toBeTruthy()
    expect(handShake.headers).toBeTruthy()
    expect(handShake.headers.swishAction).toEqual('handshake_init')
    expect(handShake.headers.swishIV).toBeTruthy()
    expect(handShake.headers.swishKey).toBeTruthy()
    expect(handShake.headers.swishNextPublic).toBeTruthy()
  })
})

describe('SwishClient.encryptRequest', () => {
  test('should throw [HYBRIDCRYPTO_REQUEST_BODY_INVALID] when you pass an invalid body', () => {
    expect(() => {
      client.encryptRequest('')
    }).toThrow('HYBRIDCRYPTO_REQUEST_BODY_INVALID')
  })

  test('should throw [HYBRIDCRYPTO_CLIENT_NEXTPUB_NOT_SET] when you have not yet made a handshake', () => {
    expect(() => {
      const client2 = new SwishClient()
      client2.encryptRequest('sadsd')
    }).toThrow('HYBRIDCRYPTO_CLIENT_NEXTPUB_NOT_SET')
  })

  test('should be able to encrypt a json object', () => {
    const response = client.encryptRequest({
      foo: 'bar',
      score: 100,
    })
    expect(response.body).toBeTruthy()
    expect(response.body.encBody).toBeTruthy()
    expect(response.body.isJson).toEqual(true)
    expect(response.headers).toBeTruthy()
    expect(response.headers.swishAction).toEqual('request_basic')
    expect(response.headers.swishKey).toBeTruthy()
    expect(response.headers.swishIV).toBeTruthy()
    expect(response.headers.swishNextPublic).toBeTruthy()
  })
})

describe('SwishClient.handleHandshakeResponse', () => {
  test('should throw [HANDSHAKE_RESPONSE_SESSID_INVALID] if provided header for swishSessionId is invalid', () => {
    expect(() => {
      client.handleHandshakeResponse({
        body: { isJson: false, encBody: '' },
        headers: {
          swishSessionId: '',
          swishAction: '',
          swishKey: '',
          swishIV: '',
          swishNextPublic: '',
        },
      })
    }).toThrow('HANDSHAKE_RESPONSE_SESSID_INVALID')
  })

  test('should throw [HANDSHAKE_RESPONSE_ACTION_INVALID] if provided header for swishAction is invalid', () => {
    expect(() => {
      client.handleHandshakeResponse({
        body: { isJson: false, encBody: '' },
        headers: {
          swishSessionId: 'adonisv79',
          swishAction: '',
          swishKey: '',
          swishIV: '',
          swishNextPublic: '',
        },
      })
    }).toThrow('HANDSHAKE_RESPONSE_ACTION_INVALID')
  })

  test('should throw [HANDSHAKE_RESPONSE_AESKEY_INVALID] if provided header for swishKey is invalid', () => {
    expect(() => {
      client.handleHandshakeResponse({
        body: { isJson: false, encBody: '' },
        headers: {
          swishSessionId: 'adonisv79',
          swishAction: 'handshake_response',
          swishKey: '',
          swishIV: '',
          swishNextPublic: '',
        },
      })
    }).toThrow('HANDSHAKE_RESPONSE_AESKEY_INVALID')
  })

  test('should throw [HANDSHAKE_RESPONSE_AESIV_INVALID] if provided header for swishIV is invalid', () => {
    expect(() => {
      client.handleHandshakeResponse({
        body: { isJson: false, encBody: '' },
        headers: {
          swishSessionId: 'adonisv79',
          swishAction: 'handshake_response',
          swishKey: key.toString('base64'),
          swishIV: '',
          swishNextPublic: '',
        },
      })
    }).toThrow('HANDSHAKE_RESPONSE_AESIV_INVALID')
  })

  test('should throw [HANDSHAKE_RESPONSE_NEXTPUBKEY_INVALID] if provided header for swishNextPublic is invalid', () => {
    expect(() => {
      client.handleHandshakeResponse({
        body: { isJson: false, encBody: '' },
        headers: {
          swishSessionId: 'adonisv79',
          swishAction: 'handshake_response',
          swishKey: key.toString('base64'),
          swishIV: iv.toString('base64'),
          swishNextPublic: '',
        },
      })
    }).toThrow('HANDSHAKE_RESPONSE_NEXTPUBKEY_INVALID')
  })

  test('should throw [HYBRIDCRYPT_ARGS_BODY_INVALID] if provided encBody is invalid', () => {
    expect(() => {
      client.handleHandshakeResponse({
        body: { isJson: false, encBody: '' },
        headers: {
          swishSessionId: 'adonisv79',
          swishAction: 'handshake_response',
          swishKey: key.toString('base64'),
          swishIV: iv.toString('base64'),
          swishNextPublic: pubKey,
        },
      })
    }).toThrow('HYBRIDCRYPT_ARGS_BODY_INVALID')
  })

  test('should be able to decrypt to original response data', () => {
    const handshakeResponse = client.generateHandshake()
    handshakeResponse.headers.swishSessionId = 'adonisv79' // simulate server new sess id response
    const serverResponse = SwishServer.handleHandshakeRequest(handshakeResponse.headers)
    const response = client.handleHandshakeResponse({
      body: serverResponse.body,
      headers: serverResponse.headers,
    })
    expect(client.SessionId).toEqual('adonisv79') // the session ID should be replaced by new response
    expect(response).toStrictEqual({ status: 'ok' })
  })
})
