# lto-crypto  [![npm version](https://badge.fury.io/js/%40lto-network%2Flto-crypto.svg)](https://www.npmjs.com/package/@lto-network/lto-crypto)

Using this library you can easily create and sign binary data for LTO Network.
It provides all you need on crypto and binary layers.

### Includes:
- Key pair generation
- Address generation
- Bytes signature
- Signature validation

### Keys and Addresses

```js
const lc = require('lto-crypto');

//Mainnet address
lc.address('seed'); //3JyGQNS7yqfKV1P2RaLE3bVyga6JAmUXVzE

//Testnet address
lc.address('seed', 'T'); //3NByEFJWHX72VYr97mgtbUW9yc8MiNpiDVo

//Public and private keys from seed
lc.keyPair('seed');

/*{
  public: '2od6By8qGe5DLYj7LD9djxVLBWVx5Dsy3P1TMRWdBPX6',
  private: '3wKoEgaFjnT8mcPS7cmpgsB6eXuo6oC4CvTBP47jFHAoXJsqiBuXSy6C3dy9wLTfRVEqhmaaj8x3ThVMMET6yN6t'
}*/

//Public only
lc.publicKey('seed'); //2od6By8qGe5DLYj7LD9djxVLBWVx5Dsy3P1TMRWdBPX6

//Private only
lc.privateKey('seed'); //3wKoEgaFjnT8mcPS7cmpgsB6eXuo6oC4CvTBP47jFHAoXJsqiBuXSy6C3dy9wLTfRVEqhmaaj8x3ThVMMET6yN6t

```

### Signatures and verification

```js
const lc = require('lto-crypto');
const { verifySignature, signBytes, publicKey } = lc;

const seed = 'magicseed';
const pubKey = publicKey(seed);

const bytes = Uint8Array.from([1, 2, 3, 4]);
const sig = signBytes(bytes, seed);
const isValid = verifySignature(pubKey, bytes, sig); //true

```
