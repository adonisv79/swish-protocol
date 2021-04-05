/* eslint-disable no-console */
import express from 'express'
import bodyParser from 'body-parser'
import { IncomingHttpHeaders } from 'http'
import { SwishServer, SwishHeaders } from '../src/index'
// lets start with a basic session handler.
const { SessionManagerBasic } = require('adon-api-session')

const session = new SessionManagerBasic()
// lets setup our web server sample using express
const port = 3000
const app = express()
app.use(bodyParser.json())

function getSwishFromReqHeaders(reqHeaders: IncomingHttpHeaders): SwishHeaders {
  const headers: SwishHeaders = {
    swishAction: '', swishToken: '', swishSessionId: '',
  }
  if (typeof reqHeaders['swish-action'] === 'string') {
    headers.swishAction = reqHeaders['swish-action']
  }
  if (typeof reqHeaders['swish-token'] === 'string') {
    headers.swishToken = reqHeaders['swish-token']
  }
  if (typeof reqHeaders['swish-sess-id'] === 'string') {
    headers.swishSessionId = reqHeaders['swish-sess-id']
  }
  console.dir(headers)
  return headers
}

// create an endpoint listening to the recommended authentication path
app.post('/auth/handshake', (req, res) => {
  try {
    console.log('################################################################################')
    console.log('***HANDSHAKE:REQUEST_ACCEPTED***')
    const headers = getSwishFromReqHeaders(req.headers)
    // generate a unique session id using a session manager
    headers.swishSessionId = (session.createSession({}) as string)
    console.log(`Session:  ${headers.swishSessionId}`)
    const result = SwishServer.handleHandshakeRequest(headers)
    // store the next request decryption items in the session
    session.find(headers.swishSessionId).decrypt = result.decrypt

    console.log('***HANDSHAKE:RESPONDING***')
    console.dir(result.body)
    res.set({
      'swish-action': result.headers.swishAction,
      'swish-token': result.headers.swishToken,
      'swish-sess-id': result.headers.swishSessionId,
    })
    console.dir(result)
    res.send(result.body)
  } catch (err) {
    console.error(err)
    res.status(500).send((err as Error).message)
  }
})

// create a test endpoint to see if data are transferred securely
app.post('/test/success', (req, res) => {
  try {
    console.log('################################################################################')
    console.log('***TEST:REQUEST_ACCEPTED***')
    // retrieve the private key and passphrase for the session and decryptRequest
    if (typeof req.headers['swish-sess-id'] === 'string'
      && !session.find(req.headers['swish-sess-id'])) {
      res.status(403).send('Invalid Session')
    }
    const privateKey = session.find(req.headers['swish-sess-id']).decrypt.nextPrivate
    const passphrase = session.find(req.headers['swish-sess-id']).decrypt.createdDate.toString()
    // get the decrypted request
    const headers = getSwishFromReqHeaders(req.headers)
    console.dir(session.find(req.headers['swish-sess-id']).decrypt)
    const decReq = SwishServer.decryptRequest(headers, req.body, privateKey, passphrase)

    console.log('***RECEIVED_REQUEST***')
    console.dir(decReq)
    const bodyObj = decReq.body as Record<string, unknown>
    let resBody
    if (bodyObj.action === 'hello' && bodyObj.passcode === 'whoami') {
      resBody = { secretResponse: `Hello ${bodyObj.message}` }
    } else if (bodyObj.action === 'move' && bodyObj.passcode === 'whereami') {
      resBody = { secretResponse: `Welcome to ${bodyObj.message}` }
    } else {
      resBody = { secretResponse: 'Unknown action, should be hello or move' }
    }
    // encrypt the response body before sending
    const response = SwishServer.encryptResponse(req.headers['swish-sess-id'] as string, resBody, decReq.nextPubKey)
    // store the next request decryption items in the session
    session.find(req.headers['swish-sess-id']).decrypt = response.decrypt

    console.log('***RESPONDED***')
    console.dir(response.body)
    console.log('********************************************************************')
    console.log('')
    res.set({
      'swish-action': response.headers.swishAction,
      'swish-token': response.headers.swishToken,
      'swish-sess-id': response.headers.swishSessionId,
    })
    return res.send(response.body)
  } catch (err) {
    console.error(err)
    return res.status(500).send((err as Error).message)
  }
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`))
