# adon-api-handshake ![npm](https://img.shields.io/npm/v/adon-api-handshake.svg) ![GitHub](https://img.shields.io/github/license/adonisv79/adon-api-handshake.svg) [![Build Status](https://travis-ci.org/adonisv79/adon-api-handshake.svg?branch=master)](https://travis-ci.org/adonisv79/adon-api-handshake)
An API Authentication Mechanism in order to monitor and manage sessions between clients and an API.

## How it works
The API Handshake is basically a Hybrid Encryption system (https://en.wikipedia.org/wiki/Hybrid_cryptosystem) which is built for managing short to medium term Client-Server sessions. This is usefull for ensuring that whenever a client needs to connect to an API, the transmitted communication medium is encrypted. On top of that, when that session is destroyed, the transmitted data are as good as gone! To continue communicating, the client needs to perform a new handshake. As of v1.1.0, we have added a double ratchet mechanism to even complicate things. :p

For more details on this project, please see the project wiki at https://github.com/adonisv79/adon-api-handshake/wiki

## Installation ![npm](https://img.shields.io/npm/v/adon-api-handshake.svg)
The module is released and available in NPMJS (https://www.npmjs.com/package/adon-api-handshake) 
```
npm install adon-api-handshake --save
```

Full guide is in the Wiki

## History
### Migration to TypeScript (added in 1.2.1)
We have started unit testing and boy it is a mess as we need to validate through several possible ways anyone will mess your code thru invalid parameter injection. We need a standardized way to strict type it and no one comes close to TypeScript such that most projects are moving towards it.

*do not use 1.2.0, it pointed to the wrong index.js file and was hotfixed via 1.2.1 

### Double Ratchet (added in 1.1.0)
We enhance the algorithm by applying a double ratchet approach similar to most messaging encryption apps. Each communication will basically generate a new private key and pass its new public key. these sets are used for the next request or response chain making it almost crazy to crack unlike in the previous version where getting the current session key allows a hacker to snoop thru ALL messages in the session. now they need to be part of the entire conversation chain or they will be lost.
