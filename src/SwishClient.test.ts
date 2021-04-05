import { SwishClient } from './SwishClient'
import { EncryptedResponse, SwishServer } from './SwishServer'

const client = new SwishClient()
let handshakeRequest
let serverResponse: EncryptedResponse

describe('SwishClient.generateHandshake', () => {
  test('should be able to generate a new handshake', () => {
    handshakeRequest = client.generateHandshake()
    expect(client.SessionId).toEqual('') // this is empty during start of handshake
    expect(handshakeRequest.body).toBeTruthy()
    expect(handshakeRequest.headers).toBeTruthy()
    expect(handshakeRequest.headers.swishAction).toEqual('handshake_init')
    expect(handshakeRequest.headers.swishToken).toBeTruthy()
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
    expect(response.headers.swishToken).toBeTruthy()
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
          swishToken: '',
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
          swishToken: '',
        },
      })
    }).toThrow('HANDSHAKE_RESPONSE_ACTION_INVALID')
  })

  test('should throw [HANDSHAKE_RESPONSE_TOKEN_INVALID] if provided header for swishToken is empty', () => {
    expect(() => {
      client.handleHandshakeResponse({
        body: { isJson: false, encBody: '' },
        headers: {
          swishSessionId: 'adonisv79',
          swishAction: 'handshake_response',
          swishToken: '',
        },
      })
    }).toThrow('HANDSHAKE_RESPONSE_TOKEN_INVALID')
  })

  test('should throw [HANDSHAKE_RESPONSE_TOKEN_INVALID] if provided header for swishToken cannot be properly parsed', () => {
    expect(() => {
      client.handleHandshakeResponse({
        body: { isJson: false, encBody: '' },
        headers: {
          swishSessionId: 'adonisv79',
          swishAction: 'handshake_response',
          swishToken: 'some_bad_token',
        },
      })
    }).toThrow('HANDSHAKE_RESPONSE_TOKEN_INVALID')
  })

  test('should throw [HYBRIDCRYPT_ARGS_BODY_INVALID] if provided encBody is invalid', () => {
    expect(() => {
      client.handleHandshakeResponse({
        body: { isJson: false, encBody: '' },
        headers: {
          swishSessionId: 'adonisv79',
          swishAction: 'handshake_response',
          swishToken: 'thisistheaesiv.thisistheaeskey.thisisthenextpublicrsakeytobeused',
        },
      })
    }).toThrow('HYBRIDCRYPT_ARGS_BODY_INVALID')
  })

  test('should be able to decrypt to original response data', () => {
    handshakeRequest = client.generateHandshake()
    handshakeRequest.headers.swishSessionId = 'adonisv79' // simulate server new sess id response
    serverResponse = SwishServer.handleHandshakeRequest(handshakeRequest.headers)
    const response = client.handleHandshakeResponse({
      body: serverResponse.body,
      headers: serverResponse.headers,
    })
    expect(client.SessionId).toEqual('adonisv79') // the session ID should be replaced by new response
    expect(response).toStrictEqual({ status: 'ok' })
  })
})
