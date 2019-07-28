# node-swish-protocol
An API Authentication Mechanism in order to monitor and manage sessions between clients and an API.

## Project stats
* Package: [![npm](https://img.shields.io/npm/v/node-swish-protocol.svg)](https://www.npmjs.com/package/node-swish-protocol) [![npm](https://img.shields.io/npm/dm/node-swish-protocol.svg)](https://www.npmjs.com/package/node-swish-protocol)
* License: [![GitHub](https://img.shields.io/github/license/adonisv79/node-swish-protocol.svg)](https://github.com/adonisv79/node-swish-protocol/blob/master/LICENSE)
* CICD: [![Codacy Badge](https://api.codacy.com/project/badge/Grade/3709f3ab3b0c4380b5a41e010e8628c0)](https://www.codacy.com/app/adonisv79/node-swish-protocol?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=adonisv79/node-swish-protocol&amp;utm_campaign=Badge_Grade) [![Known Vulnerabilities](https://snyk.io/test/github/adonisv79/node-swish-protocol/badge.svg)](https://snyk.io/test/github/adonisv79/node-swish-protocol)
  * develop: [![Build Status](https://travis-ci.org/adonisv79/node-swish-protocol.svg?branch=develop)](https://travis-ci.org/adonisv79/node-swish-protocol) [![Coverage Status](https://coveralls.io/repos/github/adonisv79/node-swish-protocol/badge.svg?branch=develop)](https://coveralls.io/github/adonisv79/node-swish-protocol?branch=develop)
  * master: [![Build Status](https://travis-ci.org/adonisv79/node-swish-protocol.svg?branch=master)](https://travis-ci.org/adonisv79/node-swish-protocol) [![Coverage Status](https://coveralls.io/repos/github/adonisv79/node-swish-protocol/badge.svg)](https://coveralls.io/github/adonisv79/node-swish-protocol)

## How it works
The API Handshake is basically a Hybrid Encryption system (https://en.wikipedia.org/wiki/Hybrid_cryptosystem) which is built for managing short to medium term Client-Server sessions. This is useful for ensuring that whenever a client needs to connect to an API, the transmitted communication on the network is encrypted e2e (End-to-End). On top of that, when that session is destroyed, the transmitted data are as good as gone! To continue communicating, the client needs to perform a new handshake. As of v1.1.0, we have added a double ratchet mechanism to even complicate things. v1.2.0 improvements focusing on strict typing inference where we have adapted the base code to TypeScript :p

For more details on this project, please see the project wiki at https://github.com/adonisv79/node-swish-protocol/wiki

## Installation
The module is released and available in NPMJS (https://www.npmjs.com/package/swish-protocol) 
```
npm install swish-protocol --save
```

Full guide is in the Wiki

## History
### renamed project to swish-protocol (as of 1.2.5)
I just had to rename it as the long name is not that awesome. SWISH stands for "Secured Web Iterating Session Handshake" which pretty much describes what it does. all headers are renamed as such as well.

### Migration to TypeScript and CICD (added in 1.2.3)
We have started unit testing and boy it is a mess as we need to validate through several possible ways anyone will mess your code thru invalid parameter injection. We need a standardized way to strict type it and no one comes close to TypeScript such that most projects are moving towards it. Modified the unit tests and code coverage as well to allow for Typescript support. We have also utilized popular open-source quality and CI tools like Codacy, Jest and Travis

*do not use 1.2.0, it pointed to the wrong index.js file and was hotfixed via 1.2.1 
*1.2.2 has a minor fix from 1.2.1 and works the same. only the file size changed as we removed the test tool codes

### Double Ratchet (added in 1.1.0)
We enhance the algorithm by applying a double ratchet approach similar to most messaging encryption apps. Each communication will basically generate a new private key and pass its new public key. these sets are used for the next request or response chain making it almost crazy to crack unlike in the previous version where getting the current session key allows a hacker to snoop thru ALL messages in the session. now they need to be part of the entire conversation chain or they will be lost.
