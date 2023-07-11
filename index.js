const crypto = require('crypto')

const paillier = require('paillier-js')
const bigInt = require('big-integer')

const rEncrypt = function ({ n, g }, message) {
  const _n2 = n.pow(2)
  let r
  do {
      r = bigInt.randBetween(2, n)
  } while (r.leq(1))
  return {r, cipher: g.modPow(bigInt(message), _n2).multiply(r.modPow(n, _n2)).mod(_n2)}
}

const getCoprime = (target) => {
  const bits = Math.floor(Math.log2(target))
  while (true) {
    const lowerBound = bigInt(2).pow(bits-1).plus(1)
    let possible = lowerBound.plus(bigInt.rand(bits)).or(1)
    const result = bigInt(possible)
    if (possible.gt(bigInt(2).pow(1024))) return result
    while(target > 0) {
      [possible, target] = [target, possible.mod(target)]
    }
    if (possible.eq(bigInt(1))) return result
  }
}

const encryptWithProof = (publicKey, message, bits=512) => {
  const {r: random, cipher} = rEncrypt(publicKey, message)

  const om = getCoprime(publicKey.n)
  const ap = om.modPow(publicKey.n, publicKey._n2)

  let proof = {}

  const gmk = publicKey.g.modPow(bigInt(message), publicKey._n2)
  const uk = cipher.times(gmk.modInv(publicKey._n2)).mod(publicKey._n2)
  
  if (message.toString() === message.toString()) {  
    proof[`a`] = ap.toString()
  } else {
    const zk = getCoprime(publicKey.n)
    const ek = bigInt.randBetween(2, bigInt(2).pow(bits).subtract(1))
    const zn = zk.modPow(publicKey.n, publicKey._n2)
    const ue = uk.modPow(ek, publicKey._n2)
    const ak = zn.times(ue.modInv(publicKey._n2)).mod(publicKey._n2)
    proof[`a`] = ak.toString()
    proof[`z`] = zk.toString()
    proof[`e`] = ek.toString()
  }

  const hash = crypto.createHash('sha256').update(Object.values(proof).filter((_, i) => i % 3 === 0).join('')).digest('hex')

  const esum = Object.values(proof).filter((_, i) => i % 3 === 2).reduce((acc, ek) => acc.plus(bigInt(ek)), bigInt(0))
  const ep = bigInt(hash, 16).subtract(esum).mod(bigInt(2).pow(256))
  const rep = random.modPow(ep, publicKey.n)
  const zp = om.times(rep).mod(publicKey.n)
  proof[`e`] = ep.toString()
  proof[`z`] = zp.toString()

  return {cipher: cipher.toString(), proof}
}

const verifyMessage = (publicKey, cipher, proof, validMessage) => {
  const cipherBigInt = bigInt(cipher)
  
  const hash = crypto.createHash('sha256').update(proof.a).digest('hex')

  const gmk = publicKey.g.modPow(validMessage, publicKey._n2)
  const uk = cipherBigInt.times(gmk.modInv(publicKey._n2)).mod(publicKey._n2)

  const ek = bigInt(proof.e)
  if (!bigInt(hash, 16).eq(ek)) {
    return false
  }

  const zk = bigInt(proof.z)
  const ak = bigInt(proof.a)
  const zkn = zk.modPow(publicKey.n, publicKey._n2)
  const uke = uk.modPow(ek, publicKey._n2)
  const akue = ak.times(uke).mod(publicKey._n2)
  
  return zkn.eq(akue)
}

function stringToBigInt(str) {
  const buf = Buffer.from(str)
  let hexString = buf.toString('hex')
  if (hexString.length % 2 != 0) {
    hexString = '0' + hexString // pad with a leading zero if necessary
  }
  return bigInt(hexString, 16)
}

module.exports = function(bits) {
  const zerok = this

  if(!bits) bits = 512
  let {publicKey, privateKey} = paillier.generateRandomKeys(bits)

  this.keypair = {publicKey, privateKey}

  this.newKey = (bits) => {
    if(!bits) bits = 512
    let keypair = paillier.generateRandomKeys(bits)
    publicKey = keypair.publicKey
    privateKey = keypair.privateKey
    this.keypair = {publicKey, privateKey}
  }

  this.proof = (message) => {
    message = stringToBigInt(message.toString())
    return encryptWithProof(publicKey, message, bits)
  }
  
  this.verify = (message, certificate, pubkey) => { 
    if(!pubkey) pubkey = publicKey
    message = stringToBigInt(message.toString())
    return verifyMessage(pubkey, certificate.cipher, certificate.proof, message)
  }
}
