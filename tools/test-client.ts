/* eslint-disable no-console */
import { BinaryLike } from 'crypto'
import axios, { AxiosResponse } from 'axios'
import { SwishClient, SwishHeaders } from '../src/index'

const SERVER_URL = 'http://localhost:3000/sapi'
const clientHS = new SwishClient()

async function testHandShake(): Promise< Buffer| Record<string, unknown>> {
  console.log('################################################################################')
  const swish = clientHS.generateHandshake()
  console.log('***HANDSHAKE:INITIATING***')
  // run the request. we don't use async await coz request-promise uses bluebird
  return axios({
    method: 'post',
    url: `${SERVER_URL}`,
    responseType: 'json',
    headers: {
      'swish-action': swish.headers.swishAction,
      'swish-token': swish.headers.swishToken,
      'swish-sess-id': swish.headers.swishSessionId,
    },
    data: swish.body,
  }).then((response: AxiosResponse) => {
    console.log('***HANDSHAKE:RECEIVED***')
    const swishheaders: SwishHeaders = {
      swishAction: (response.headers['swish-action'] || '').toString(),
      swishToken: (response.headers['swish-token'] || '').toString(),
      swishSessionId: (response.headers['swish-sess-id'] || '').toString(),
    }
    const dec: Buffer | Record<string, unknown> = clientHS.handleHandshakeResponse({
      headers: swishheaders, body: response.data,
    })
    console.dir(dec)
    return dec
  })
}

async function testRequest(body: BinaryLike | Record<string, unknown>): Promise<void> {
  console.log('***SENDING***')
  console.dir(body)
  const swish = clientHS.encryptRequest(body)
  // run the request. we don't use async await coz request-promise uses bluebird
  return axios({
    url: `${SERVER_URL}/test/success`,
    method: 'post',
    responseType: 'json',
    headers: {
      'swish-action': swish.headers.swishAction,
      'swish-token': swish.headers.swishToken,
      'swish-sess-id': swish.headers.swishSessionId,
    },
    data: swish.body,
  }).then((response: AxiosResponse) => {
    const swishheaders: SwishHeaders = {
      swishAction: (response.headers['swish-action'] || '').toString(),
      swishToken: (response.headers['swish-token'] || '').toString(),
      swishSessionId: (response.headers['swish-sess-id'] || '').toString(),
    }
    console.log('********************************************************************')
    console.log(response.headers)
    console.log('********************************************************************')
    const dec = clientHS.decryptResponse({
      headers: swishheaders, body: response.data,
    })
    console.log('***RECEIVED_RESPONSE***')
    console.dir(dec)
    console.log('********************************************************************')
    console.log('')
  }).catch((err: Error) => {
    console.error(err.message)
  })
}

async function test(): Promise<void> {
  try {
    const handshakeResponse = (await testHandShake()) as Record<string, unknown>
    if (handshakeResponse.status === 'ok') {
      console.log('[SUCCESS]HANDSHAKE_PAIRED')
    } else {
      throw new Error('HANDSHAKE_FAILED')
    }

    // now lets start communicating to the secured endpoints
    await testRequest({
      action: 'hello', message: 'Adonis Villamor', passcode: 'whoami',
    })

    // send a different one this time
    await testRequest({ action: 'move', message: 'Japan', passcode: 'whereami' })
  } catch (err) {
    console.error(err.message)
  }
}

test()
