# adon-api-handshake
An API Authentication mechanism in order to monitor and manage sessions with an API

## How it works
The API Handshake is basically a Hybrid Encryption system (https://en.wikipedia.org/wiki/Hybrid_cryptosystem) which is built for managing short to medium term Client-Server sessions. This is usefull for ensuring that whenever a client needs to connect to an API, the transmitted communication medium is encrypted. On top of that, when that session is destryed, the client performs a new handshake generating new session communication channels such that anyone who manages to get the keys to the prvious session cannot reuse the same keys on the new session.
