# swish-protocol
![swish protocol banner](https://adonisv79.github.io/swish-protocol/images/banner.png)
An API Authentication Mechanism in order to monitor and manage sessions between clients and an API.

## Project stats
* Package: [![npm](https://img.shields.io/npm/v/swish-protocol.svg)](https://www.npmjs.com/package/swish-protocol) [![npm](https://img.shields.io/npm/dm/swish-protocol.svg)](https://www.npmjs.com/package/swish-protocol)
* License: [![GitHub](https://img.shields.io/github/license/adonisv79/swish-protocol.svg)](https://github.com/adonisv79/swish-protocol/blob/master/LICENSE)
* CICD: [![Codacy Badge](https://app.codacy.com/project/badge/Grade/384bdaeb318b42039b9f1d3b723e1e3d)](https://www.codacy.com/gh/adonisv79/swish-protocol/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=adonisv79/swish-protocol&amp;utm_campaign=Badge_Grade) [![Known Vulnerabilities](https://snyk.io/test/github/adonisv79/swish-protocol/badge.svg)](https://snyk.io/test/github/adonisv79/swish-protocol)
  * develop: [![Build Status](https://travis-ci.com/adonisv79/swish-protocol.svg?branch=develop)](https://travis-ci.com/adonisv79/swish-protocol) [![Coverage Status](https://coveralls.io/repos/github/adonisv79/swish-protocol/badge.svg?branch=master)](https://coveralls.io/github/adonisv79/swish-protocol?branch=develop)
  * master: [![Build Status](https://travis-ci.com/adonisv79/swish-protocol.svg?branch=master)](https://travis-ci.com/adonisv79/swish-protocol) [![Coverage Status](https://coveralls.io/repos/github/adonisv79/swish-protocol/badge.svg?branch=master)](https://coveralls.io/github/adonisv79/swish-protocol?branch=master)

  

## How it works
The API Handshake is basically a Hybrid Encryption system (https://en.wikipedia.org/wiki/Hybrid_cryptosystem) which is built for managing short to medium term Client-Server sessions. This is useful for ensuring that whenever a client needs to connect to an API, the transmitted communication on the network is encrypted e2e (End-to-End). On top of that, when that session is destroyed, the transmitted data are as good as gone! To continue communicating, the client needs to perform a new handshake. To ensure that keys cannot be reused, it also implements the double ratchet algorithm (https://en.wikipedia.org/wiki/Double_Ratchet_Algorithm).

For more details on this project, please see the project wiki at https://github.com/adonisv79/node-swish-protocol/wiki

## Installation
The module is released and available in NPMJS (https://www.npmjs.com/package/swish-protocol) 
```
npm install swish-protocol --save
```

## Building source
Just run 'tsc' and it will build the entire distributable Javascript and description files (*.d.ts) into the 'dist/src' folder. This will also build the dev testing output into 'dist/tools'. Note that when this is published ('npm publish .'), only the files in 'dist/src' is included.

## Running test server and client
After building, you can run the scripts in package json to test the server and client communications (files found in 'dist/tools')
```
npm run dist:server
npm run dist:client
```

## History
### Simplified headers for keys into a single token (2.5.0)
The previous swishIv, swishKey and swishnextPub is now a dot (.) concatenated base64 string named swishToken. 

### Fixed CICD and Typescript+AirBnb linting policies (2.4.0)
automated publish and fixed several CICD integrations. Server and Client classes functionalities are now made static

### Fixed hybrid decryption response (2.3.0)
Major improvements in code fixing several pending code quality fixes and type definition improvements

### Fixed hybrid decryption response (2.0.1)
* it now uses HybridDecryptResult which returns the decrypted data as buffer and the next public key in the chain.
* SwishBody's 'enc_body' no longer allows undefined

### Major revamp (2.0.0)
* Just updated several issues from previous versions and made it much simpler to understand the core concepts of the tool. 
* fixed crlf inconsistencies
* Added snyk for dependency validation. 
* Updated to also use eslint AirBnB with Typescript and removed deprecated tslint. 
* Most functions have been simplified and thus will break any previous implementation so make sure to always lock your versions.

### renamed project to swish-protocol (as of 1.2.5)
I just had to rename it as the long name is not that awesome. SWISH stands for "Secured Web Iterating Session Handshake" which pretty much describes what it does. all headers are renamed as such as well.

### Migration to TypeScript and CICD (added in 1.2.3)
We have started unit testing and boy it is a mess as we need to validate through several possible ways anyone will mess your code thru invalid parameter injection. We need a standardized way to strict type it and no one comes close to TypeScript such that most projects are moving towards it. Modified the unit tests and code coverage as well to allow for Typescript support. We have also utilized popular open-source quality and CI tools like Codacy, Jest and Travis

*do not use 1.2.0, it pointed to the wrong index.js file and was hotfixed via 1.2.1 
*1.2.2 has a minor fix from 1.2.1 and works the same. only the file size changed as we removed the test tool codes

### Double Ratchet (added in 1.1.0)
We enhance the algorithm by applying a double ratchet approach similar to most messaging encryption apps. Each communication will basically generate a new private key and pass its new public key. these sets are used for the next request or response chain making it almost crazy to crack unlike in the previous version where getting the current session key allows a hacker to snoop thru ALL messages in the session. now they need to be part of the entire conversation chain or they will be lost.
