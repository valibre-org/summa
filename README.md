# Substrate meets Matrix

Summa is a group of initiatives that bridge the Matrix protocol with Substrate based blockchains.  

- Subot: A configurable matrix bot that can act as your personal blockchain assitant.
- Account integration: Substrate can leverage the fact Matrix already deals with multi-device key management and mapping those keys from human friendly identifiers(Matrix ID) which can in turn be mapped from third-party identifiers like mobile phone numbers and emails. Together with the account proxies and anonymous proxy primitives powerful yet simple to use account management can emerge.
- Chat rooms with extended blockchain functionality: Custom events can signal compatible clients that a transaction needs to be signed and submitted to the chain described in the room's metadata.
- Custom query items for the now standardized `matrix://` protocol [URI scheme](https://github.com/matrix-org/matrix-doc/blob/master/proposals/2312-matrix-uri.md): Compatible Matrix+Substrate wallets can register themselves to handle the matrix protocol and in turn handle custom blockchain-related parameters which would for example allow users sharing links or QR codes that take users to a chat room with where a transaction is pre-filled and only needs signing.
