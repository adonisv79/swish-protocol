import { BinaryLike } from 'crypto';
import rp from 'request-promise';
import { Response } from 'request';
import { HandshakeClient, SwishHeaders } from '../src/index';

const SERVER_URL = 'http://localhost:3000';
const clientHS = new HandshakeClient();

async function testHandShake() {
  console.log('################################################################################');
  const swish = clientHS.generateHandshake();
  console.log('***HANDSHAKE:INITIATING***');
  // run the request. we don't use async await coz request-promise uses bluebird
  return rp({
    body: swish.body,
    headers: {
      'swish-action': swish.headers.swishAction,
      'swish-iv': swish.headers.swishIV,
      'swish-key': swish.headers.swishKey,
      'swish-next': swish.headers.swishNextPublic,
      'swish-sess-id': swish.headers.swishSessionId,
    },
    json: true,
    method: 'POST',
    resolveWithFullResponse: true,
    uri: `${SERVER_URL}/auth/handshake`,
  }).then((response: Response) => {
    console.log('***HANDSHAKE:RECEIVED***');
    const swishheaders: SwishHeaders = {
      swishAction: (response.headers['swish-action'] || '').toString(),
      swishIV: (response.headers['swish-iv'] || '').toString(),
      swishKey: (response.headers['swish-key'] || '').toString(),
      swishNextPublic: (response.headers['swish-next'] || '').toString(),
      swishSessionId: (response.headers['swish-sess-id'] || '').toString(),
    };
    const dec: any = clientHS.handleHandshakeResponse(swishheaders, response.body);
    console.dir(dec);
    return dec;
  }).catch((err: Error) => {
    console.error(err.message);
  });
}

async function testRequest(body: BinaryLike | object) {
  console.log('***SENDING***');
  console.dir(body);
  const swish = clientHS.encryptRequest(body);
  // run the request. we don't use async await coz request-promise uses bluebird
  return rp({
    body: swish.body,
    headers: {
      'swish-action': swish.headers.swishAction,
      'swish-iv': swish.headers.swishIV,
      'swish-key': swish.headers.swishKey,
      'swish-next': swish.headers.swishNextPublic,
      'swish-sess-id': swish.headers.swishSessionId,
    },
    json: true,
    method: 'POST',
    resolveWithFullResponse: true,
    uri: `${SERVER_URL}/test`,
  }).then((response: Response) => {
    const swishheaders: SwishHeaders = {
      swishAction: (response.headers['swish-action'] || '').toString(),
      swishIV: (response.headers['swish-iv'] || '').toString(),
      swishKey: (response.headers['swish-key'] || '').toString(),
      swishNextPublic: (response.headers['swish-next'] || '').toString(),
      swishSessionId: (response.headers['swish-sess-id'] || '').toString(),
    };
    console.log('********************************************************************');
    console.log(response.headers);
    console.log('********************************************************************');
    const dec: any = clientHS.decryptResponse(swishheaders, response.body);
    console.log('***RECEIVED_RESPONSE***');
    console.dir(dec);
    console.log('********************************************************************');
    console.log('');
  }).catch((err: Error) => {
    console.error(err.message);
  });
}

async function test() {
  try {
    const handshakeResponse = await testHandShake();

    if (handshakeResponse.status === 'ok') {
      console.log('[SUCCESS]HANDSHAKE_PAIRED');
    } else {
      throw new Error('HANDSHAKE_FAILED');
    }

    // now lets start communicating to the secured endpoints
    await testRequest({
      action: 'hello', message: 'Adonis Villamor', passcode: 'whoami',
    });

    // send a different one this time
    await testRequest({ action: 'move', message: 'Japan', passcode: 'whereami' });
  } catch (err) {
    console.error(err.message);
  }
}

test();
