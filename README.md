# ZeroK
> Zero knowledge proof certification and validation for any datatype

ZeroK provides a simple API for message certification and verification without the verifier needing to know anything about the message contents.

It accepts any datatype which is converted to string, encryped, then a zero knowledge proof certificate is generated for later message verification.

Zerok was inspired by the Paillier Zero Knowledge Proof code from this [presentation](https://github.com/framp/zero-knowledge-node/tree/master).

## Example
```js
const Zerok = require('./index.js')

const zerok = new Zerok(512)

let message = Math.random() // message to verify
let proof = zerok.proof(message)

let pubkey = zerok.keypair.publicKey
let isValid = zerok.verify(message, proof, pubkey)
console.log('Valid:', isValid) // true

let corruptedMessage = message + 1

let isNotValid = zerok.verify(corruptedMessage, proof, pubkey)
console.log('Valid:', isNotValid) // false

keypair = zerok.newKey(32)
pubkey = zerok.keypair.publicKey
isNotValid = zerok.verify(message, proof, pubkey)
console.log('Valid:', isNotValid) // false
```
## Install

### Node
```js
npm i zerok
```

#### Test
```js
npm run test
```

#### Browser
```html
<script src="https://cdn.jsdelivr.net/gh/draeder/zerok@master/dist/zerok.dist.js">
const zerok = new Zerok(512)
// ...
</script>
```

## Usage

### API
#### Methods
##### `new Zerok(bits[integer])` default = 512
Creates an instance of Zerok to certify messages with keys created with the passed in bit length

##### `zerok.newKey(bits[integer])` default = 512
Generates keypair used to certify the next message

##### `zerok.proof(message[number | string | object | array | buffer])`
Returns a proof certificate object for the passed in message

##### `zerok.verify(message[number | string | object | array | buffer], proof[object]), pubkey[object]`
Verifies that the passed in message matches the original certified by the passed in proof certificate object and pubkey object

#### Properties
##### `zerok.keypair [object]`
Returns the instance's current keypair
> **⚠️ Warning** The `privateKey` is sensitive data and should never be shared!

This property is provided to allow developers more flexibility in how they use this library. Please take proper security precautions into consideration if using! It is the zerok instance password! If storing, it should be stored securely.
