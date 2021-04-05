import { SwishServer } from './SwishServer'
import { SwishHeaders, HybridCryptography } from './HybridCryptography'

// prepare the keys for testing
const passphrase = 'hakunamatata'
const { key, iv } = HybridCryptography.createAESEncryptionKey()
const { pvtKey, pubKey } = HybridCryptography.createRSAEncrytptionKeys(passphrase)
const nextPubkey = HybridCryptography.aesEncrypt(pubKey, { key, iv })

describe('SwishServer.handleHandshakeRequest', () => {
  const headers: SwishHeaders = {
    swishAction: '',
    swishSessionId: '',
    swishToken: '',
  }

  test('should ensure there is a sessionId value to associate the session with', () => {
    try {
      SwishServer.handleHandshakeRequest(headers)
    } catch (err) {
      expect((err as Error).message).toMatch('SESSION_ID_INVALID')
    }
  })

  test('should ensure the swishAction value is handshake_init', () => {
    try {
      headers.swishSessionId = 'adonisv79'
      headers.swishAction = 'something_else'
      SwishServer.handleHandshakeRequest(headers)
    } catch (err) {
      expect((err as Error).message).toMatch('HANDSHAKE_INVALID_INIT')
    }
  })

  test('should ensure the swishKey is of correct length', () => {
    try {
      headers.swishSessionId = 'adonisv79'
      headers.swishAction = 'handshake_init'
      headers.swishToken = `BadAesIv.${key.toString('base64')}.${nextPubkey}`
      SwishServer.handleHandshakeRequest(headers)
    } catch (err) {
      expect((err as Error).message).toMatch('HEADER_SWISH_TOKEN_INVALID')
    }
  })

  test('should ensure the swishKey is of correct length', () => {
    try {
      headers.swishSessionId = 'adonisv79'
      headers.swishAction = 'handshake_init'
      headers.swishToken = `${iv.toString('base64')}.BadAesKey.${nextPubkey}`
      SwishServer.handleHandshakeRequest(headers)
    } catch (err) {
      expect((err as Error).message).toMatch('HEADER_SWISH_TOKEN_INVALID')
    }
  })

  test('should ensure the swishNextPublic is of correct length', () => {
    try {
      headers.swishSessionId = 'adonisv79'
      headers.swishAction = 'handshake_init'
      headers.swishToken = `${iv.toString('base64')}.${key.toString('base64')}.fakepubkey`
      SwishServer.handleHandshakeRequest(headers)
    } catch (err) {
      expect((err as Error).message).toMatch('HEADER_SWISH_TOKEN_INVALID')
    }
  })

  test('should ensure the swishNextPublic is valid for decryption using the key and iv', () => {
    try {
      headers.swishSessionId = 'adonisv79'
      headers.swishAction = 'handshake_init'
      headers.swishToken = `${iv.toString('base64')}.${key.toString('base64')}.thisisabrokennextpublickey`
      SwishServer.handleHandshakeRequest(headers)
    } catch (err) {
      expect((err as Error).message).toMatch('HANDSHAKE_NEXTPUBKEY_DECRYPT_FAILED')
    }
  })

  test('should respond the new randomized key sets based submitted request', () => {
    headers.swishSessionId = 'adonisv79'
    headers.swishAction = 'handshake_init'
    headers.swishToken = `${iv.toString('base64')}.${key.toString('base64')}.${nextPubkey}`
    const result = SwishServer.handleHandshakeRequest(headers)
    expect(result.headers.swishSessionId).toBe(headers.swishSessionId)
    expect(result.headers.swishAction).toBe('handshake_response')
    expect(result.headers.swishToken).toBeTruthy()
    // try to decrypt the data and analyze its content
    expect(result.body.encBody).toBeTruthy()
    const swishKeys = HybridCryptography.retrieveKeysFromSwishToken(result.headers.swishToken)
    const bodyDec = HybridCryptography.hybridDecrypt(
      result.body, swishKeys, pvtKey, passphrase,
    )
    expect(bodyDec.data).toStrictEqual({ status: 'ok' })
    expect(bodyDec.nextPublic).toBeTruthy()
  })
})

describe('SwishServer.decryptRequest', () => {
  const headers: SwishHeaders = {
    swishSessionId: 'adonisv79',
    swishAction: 'handshake_init',
    swishToken: '',
  }
  let encBody: string
  let nextServerPrivate: string
  let serverKeyCreatedDate: number

  beforeEach(() => {
    // we need to create a handshake and retrieve the next decryption mechanism of the server
    const handshakeResult = SwishServer.handleHandshakeRequest({
      swishSessionId: 'adonisv79',
      swishAction: 'handshake_init',
      swishToken: `${iv.toString('base64')}.${key.toString('base64')}.${nextPubkey}`,
    })
    nextServerPrivate = handshakeResult.decrypt.nextPrivate
    serverKeyCreatedDate = handshakeResult.decrypt.createdDate

    const swishKeys = HybridCryptography.retrieveKeysFromSwishToken(handshakeResult.headers.swishToken)
    const hDecResult = HybridCryptography.hybridDecrypt(
      handshakeResult.body, swishKeys, pvtKey, passphrase,
    )

    const newRequest = HybridCryptography.hybridEncrypt({ foo: 'bar', score: 100 }, hDecResult.nextPublic)
    headers.swishToken = HybridCryptography.createSwishToken(newRequest.keys.aesIV, newRequest.keys.aesKey, newRequest.keys.rsaNextPublic)
    encBody = newRequest.body.encBody
  })

  test('should throw [HYBRIDCRYPT_ARGS_BODY_INVALID] if server encrypted body is invalid', () => {
    expect(() => {
      SwishServer.decryptRequest(
        headers,
        { encBody: '', isJson: true },
        nextServerPrivate,
        serverKeyCreatedDate.toString(),
      )
    }).toThrow('HYBRIDCRYPT_ARGS_BODY_INVALID')
  })

  test('should throw [HYBRIDCRYPT_ARGS_PVTKEY_INVALID] if server private key is invalid', () => {
    expect(() => {
      SwishServer.decryptRequest(
        headers,
        { encBody, isJson: true },
        '',
        serverKeyCreatedDate.toString(),
      )
    }).toThrow('HYBRIDCRYPT_ARGS_PVTKEY_INVALID')
  })

  test('should throw an error when you pass an empty passphrase', () => {
    expect(() => {
      SwishServer.decryptRequest(
        headers,
        { encBody, isJson: true },
        nextServerPrivate,
        '',
      )
    }).toThrow('HYBRIDCRYPT_ARGS_PASSPHRASE_INVALID')
  })

  test('should throw an error when you pass a wrong passphrase', () => {
    expect(() => {
      SwishServer.decryptRequest(
        headers,
        { encBody, isJson: true },
        nextServerPrivate,
        'wrong passphrase',
      )
    }).toThrowError()
  })

  test('should throw [HYBRIDCRYPT_HDEC_AESIV_FAILED] when you pass a wrong iv in the token', () => {
    expect(() => {
      const tokenKeys = headers.swishToken.split('.')
      SwishServer.decryptRequest(
        {
          swishSessionId: headers.swishSessionId,
          swishAction: headers.swishAction,
          swishToken: `aninvalidaesiv==.${tokenKeys[1]}.${tokenKeys[2]}`,
        },
        { encBody, isJson: true },
        nextServerPrivate,
        serverKeyCreatedDate.toString(),
      )
    }).toThrow('HYBRIDCRYPT_HDEC_AESIV_FAILED')
  })

  test('should throw [HYBRIDCRYPT_HDEC_AESKEY_FAILED] when you pass a wrong AES key in the token', () => {
    expect(() => {
      const tokenKeys = headers.swishToken.split('.')
      SwishServer.decryptRequest(
        {
          swishSessionId: headers.swishSessionId,
          swishAction: headers.swishAction,
          swishToken: `${tokenKeys[0]}.aninvalidaeskey==.${tokenKeys[2]}`,
        },
        { encBody, isJson: true },
        nextServerPrivate,
        serverKeyCreatedDate.toString(),
      )
    }).toThrow('HYBRIDCRYPT_HDEC_AESKEY_FAILED')
  })

  test('should throw [HYBRIDCRYPT_HDEC_BODY_FAILED] when you pass the wrong body (not decryptable by given keys)', () => {
    expect(() => {
      SwishServer.decryptRequest(
        {
          swishSessionId: headers.swishSessionId,
          swishAction: headers.swishAction,
          swishToken: headers.swishToken,
        },
        { encBody: 'this should break', isJson: true },
        nextServerPrivate,
        serverKeyCreatedDate.toString(),
      )
    }).toThrow('HYBRIDCRYPT_HDEC_BODY_FAILED')
  })

  test('should throw [HYBRIDCRYPT_HDEC_NEXTPUB_FAILED] when you pass a wrong next pub key', () => {
    expect(() => {
      const tokenKeys = headers.swishToken.split('.')
      SwishServer.decryptRequest(
        {
          swishSessionId: headers.swishSessionId,
          swishAction: headers.swishAction,
          swishToken: `${tokenKeys[0]}.${tokenKeys[1]}.thisisaninvalidnextpublickey`,
        },
        { encBody, isJson: true },
        nextServerPrivate,
        serverKeyCreatedDate.toString(),
      )
    }).toThrow('HYBRIDCRYPT_HDEC_NEXTPUB_FAILED')
  })

  test('should successfully retrieve the request body but return buffered string value isJson set to false', () => {
    const decResponse = SwishServer.decryptRequest(
      headers,
      { encBody, isJson: false },
      nextServerPrivate,
      serverKeyCreatedDate.toString(),
    )
    expect(decResponse.body).toStrictEqual(Buffer.from(JSON.stringify({ foo: 'bar', score: 100 })))
    expect(decResponse.nextPubKey).toBeTruthy()
  })

  test('should successfully retrieve the request body and generate the next pub key', () => {
    const decResponse = SwishServer.decryptRequest(
      headers,
      { encBody, isJson: true },
      nextServerPrivate,
      serverKeyCreatedDate.toString(),
    )
    expect(decResponse.body).toStrictEqual({ foo: 'bar', score: 100 })
    expect(decResponse.nextPubKey).toBeTruthy()
  })
})

describe('SwishServer.encryptResponse', () => {
  test('should throw [PUBLIC_KEY_INVALID] if provided public key is invalid', () => {
    expect(() => {
      SwishServer.encryptResponse('adonisv79', { foo: 'bar' }, '')
    }).toThrow('PUBLIC_KEY_INVALID')
  })

  test('should throw [BODY_INVALID] if provided response body is falsey', () => {
    expect(() => {
      SwishServer.encryptResponse('adonisv79', '', pubKey)
    }).toThrow('BODY_INVALID')
  })

  test('should return the complete encrypted response with decryption keys', () => {
    const encData = SwishServer.encryptResponse('adonisv79', { foo: 'bar' }, pubKey)
    expect(encData.body).toBeTruthy()
    expect(encData.body.encBody).toBeTruthy()
    expect(encData.body.isJson).toBeTruthy()
    expect(encData.body).toBeTruthy()
    expect(encData.decrypt).toBeTruthy()
    expect(encData.decrypt.createdDate).toBeTruthy()
    expect(encData.decrypt.nextPrivate).toBeTruthy()
    expect(encData.headers).toBeTruthy()
    expect(encData.headers.swishSessionId).toEqual('adonisv79')
    expect(encData.headers.swishAction).toEqual('encrypt_response')
    expect(encData.headers.swishToken).toBeTruthy()
  })
})
