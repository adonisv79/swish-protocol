# adon-api-handshake
An API Authentication mechanism in order to monitor and manage sessions with an API

## How it works
The API Handshake is basically a Hybrid Encryption system (https://en.wikipedia.org/wiki/Hybrid_cryptosystem) which is built for managing short to medium term Client-Server sessions. This is usefull for ensuring that whenever a client needs to connect to an API, the transmitted communication medium is encrypted. On top of that, when that session is destryed, the client performs a new handshake generating new session communication channels such that anyone who manages to get the keys to the prvious session cannot reuse the same keys on the new session.

## Double Ratchet (added in 1.1.0)
We enhance the algorithm by applying a double ratchet approach similar to most messaging encryption apps. Each communication will basically generate a new private key and pass its new public key. these sets are used for the next request or response chain making it almost crazy to crack unlike in the previous version where getting the current session key allows a hacker to snoop thru ALL messages in the session. now they need to be part of the entire conversation chain or they will be lost.
