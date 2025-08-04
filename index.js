const crypto = require('crypto')
const paillier = require('paillier-js')
const bigInt = require('big-integer')

/**
 * Secure cryptographically strong random number generator
 */
function secureRandom(bits) {
  const bytes = Math.ceil(bits / 8)
  const randomBytes = crypto.randomBytes(bytes)
  let result = bigInt(0)
  for (let i = 0; i < randomBytes.length; i++) {
    result = result.shiftLeft(8).add(randomBytes[i])
  }
  return result
}

/**
 * Secure random number generation within a range
 */
function secureRandomBetween(min, max) {
  if (min.geq(max)) {
    throw new Error('Invalid range: min must be less than max')
  }
  
  const range = max.subtract(min)
  
  // For very small ranges, use a simpler approach
  if (range.leq(1000)) {
    const randomValue = bigInt(crypto.randomBytes(4).readUInt32BE(0))
    return randomValue.mod(range).add(min)
  }
  
  const bits = range.bitLength().valueOf() + 8
  
  let candidate
  let attempts = 0
  const maxAttempts = 50 // Reduced from 1000 to fail faster
  
  do {
    if (attempts >= maxAttempts) {
      // Fallback: use modular arithmetic
      const randomBytes = crypto.randomBytes(Math.ceil(bits / 8))
      let fallbackResult = bigInt(0)
      for (let i = 0; i < randomBytes.length; i++) {
        fallbackResult = fallbackResult.shiftLeft(8).add(randomBytes[i])
      }
      return fallbackResult.mod(range).add(min)
    }
    candidate = secureRandom(bits)
    attempts++
  } while (candidate.geq(range))
  
  return candidate.add(min)
}

/**
 * Input validation for public keys
 */
function validatePublicKey(publicKey) {
  if (!publicKey || !publicKey.n || !publicKey.g || !publicKey._n2) {
    throw new Error('Invalid public key structure')
  }
  
  if (publicKey.n.leq(1) || publicKey.g.leq(1)) {
    throw new Error('Invalid public key parameters')
  }
  
  return true
}

/**
 * Secure conversion from string to BigInt with length validation
 */
function secureStringToBigInt(str) {
  // Handle null and undefined
  if (str === null || str === undefined) {
    str = 'null'
  } else if (typeof str !== 'string') {
    str = str.toString()
  }
  
  // Prevent excessively long inputs that could cause DoS
  if (str.length > 10000) {
    throw new Error('Input string too long')
  }
  
  const buf = Buffer.from(str, 'utf8')
  let hexString = buf.toString('hex')
  
  if (hexString.length % 2 !== 0) {
    hexString = '0' + hexString
  }
  
  const result = bigInt(hexString, 16)
  
  // Ensure the result is at least 2 for cryptographic operations
  return result.eq(0) ? bigInt(2) : result.eq(1) ? bigInt(2) : result
}

/**
 * Secure Paillier encryption with proper randomness
 */
function secureEncrypt(publicKey, message) {
  validatePublicKey(publicKey)
  
  if (!message || typeof message.leq !== 'function' || message.leq(0)) {
    throw new Error('Invalid message for encryption')
  }
  
  const _n2 = publicKey.n.pow(2)
  let r
  let attempts = 0
  const maxAttempts = 100
  
  do {
    if (attempts >= maxAttempts) {
      throw new Error('Failed to generate valid random value for encryption')
    }
    try {
      r = secureRandomBetween(bigInt(2), publicKey.n)
      if (!r || typeof r.leq !== 'function') {
        throw new Error('Invalid random value generated')
      }
    } catch (error) {
      attempts++
      continue
    }
    attempts++
  } while (r && r.leq && r.leq(1) && attempts < maxAttempts)
  
  if (!r || !r.leq || r.leq(1)) {
    throw new Error('Failed to generate valid random value')
  }
  
  const cipher = publicKey.g.modPow(message, _n2).multiply(r.modPow(publicKey.n, _n2)).mod(_n2)
  
  return { r, cipher }
}

/**
 * Generate secure proof using improved logic
 */
function generateSecureProof(publicKey, message, bits) {
  validatePublicKey(publicKey)
  
  if (bits < 256) {
    throw new Error('Minimum key size is 256 bits for security')
  }
  
  if (!message || typeof message.leq !== 'function') {
    throw new Error('Invalid message: must be a valid BigInt')
  }
  
  const { r: random, cipher } = secureEncrypt(publicKey, message)
  
  // Generate commitment value
  let w
  let attempts = 0
  const maxAttempts = 100
  
  do {
    if (attempts >= maxAttempts) {
      throw new Error('Failed to generate valid commitment value')
    }
    try {
      w = secureRandomBetween(bigInt(2), publicKey.n)
      if (!w || typeof w.leq !== 'function') {
        throw new Error('Invalid random value generated')
      }
    } catch (error) {
      attempts++
      continue
    }
    attempts++
  } while (w && w.leq && w.leq(1) && attempts < maxAttempts)
  
  if (!w || !w.leq || w.leq(1)) {
    throw new Error('Failed to generate valid commitment value')
  }
  
  const commitment = w.modPow(publicKey.n, publicKey._n2)
  
  // Create hash challenge (Fiat-Shamir heuristic)
  const challengeInput = cipher.toString() + '|' + commitment.toString()
  const hash = crypto.createHash('sha256').update(challengeInput).digest('hex')
  const challenge = bigInt(hash, 16).mod(publicKey.n)
  
  // Calculate response: z = w * r^e mod n
  const response = w.multiply(random.modPow(challenge, publicKey.n)).mod(publicKey.n)
  
  return {
    cipher: cipher.toString(),
    proof: {
      commitment: commitment.toString(),
      challenge: challenge.toString(),
      response: response.toString()
    }
  }
}

/**
 * Verify secure proof
 */
function verifySecureProof(publicKey, cipher, proof, validMessage) {
  try {
    validatePublicKey(publicKey)
    
    if (!proof || !proof.commitment || !proof.challenge || !proof.response) {
      return false
    }
    
    if (!validMessage || typeof validMessage.leq !== 'function') {
      return false
    }
    
    const cipherBigInt = bigInt(cipher)
    const commitment = bigInt(proof.commitment)
    const challenge = bigInt(proof.challenge)
    const response = bigInt(proof.response)
    
    // Verify challenge was computed correctly
    const challengeInput = cipher + '|' + proof.commitment
    const hash = crypto.createHash('sha256').update(challengeInput).digest('hex')
    const expectedChallenge = bigInt(hash, 16).mod(publicKey.n)
    
    if (!challenge.eq(expectedChallenge)) {
      return false
    }
    
    // Verify: z^n = commitment * (c/g^m)^e (mod n^2)
    const leftSide = response.modPow(publicKey.n, publicKey._n2)
    
    const gm = publicKey.g.modPow(validMessage, publicKey._n2)
    const r = cipherBigInt.multiply(gm.modInv(publicKey._n2)).mod(publicKey._n2)
    const rightSide = commitment.multiply(r.modPow(challenge, publicKey._n2)).mod(publicKey._n2)
    
    return leftSide.eq(rightSide)
  } catch (error) {
    return false
  }
}

/**
 * Main SecureZeroK class
 */
module.exports = function SecureZeroK(bits) {
  // Input validation
  if (bits && (bits < 256 || bits > 4096)) {
    throw new Error('Key size must be between 256 and 4096 bits')
  }
  
  bits = bits || 512
  
  let { publicKey, privateKey } = paillier.generateRandomKeys(bits)
  
  this.keypair = { publicKey, privateKey }
  
  this.newKey = (newBits) => {
    if (newBits && (newBits < 256 || newBits > 4096)) {
      throw new Error('Key size must be between 256 and 4096 bits')
    }
    
    newBits = newBits || 512
    const keypair = paillier.generateRandomKeys(newBits)
    publicKey = keypair.publicKey
    privateKey = keypair.privateKey
    this.keypair = { publicKey, privateKey }
    bits = newBits
  }
  
  this.proof = (message) => {
    if (message === undefined) {
      message = 'undefined'
    }
    
    const messageBigInt = secureStringToBigInt(message)
    
    if (!messageBigInt || typeof messageBigInt.leq !== 'function') {
      throw new Error('Failed to convert message to valid BigInt')
    }
    
    // Ensure we have valid publicKey before calling generateSecureProof
    if (!publicKey || !publicKey.n || !publicKey.g) {
      throw new Error('Invalid public key state')
    }
    
    return generateSecureProof(publicKey, messageBigInt, bits)
  }
  
  this.verify = (message, certificate, pubkey) => {
    try {
      if (message === undefined) {
        message = 'undefined'
      }
      if (!pubkey) pubkey = publicKey
      if (!certificate || !certificate.cipher || !certificate.proof) {
        return false
      }
      
      const messageBigInt = secureStringToBigInt(message)
      return verifySecureProof(pubkey, certificate.cipher, certificate.proof, messageBigInt)
    } catch (error) {
      return false
    }
  }
  
  this.getPublicKey = () => {
    return {
      n: publicKey.n.toString(),
      g: publicKey.g.toString(),
      _n2: publicKey._n2.toString()
    }
  }
  
  this.verifyWithSerializedKey = (message, certificate, serializedPubKey) => {
    try {
      if (message === undefined) {
        message = 'undefined'
      }
      if (!certificate || !certificate.cipher || !certificate.proof) {
        return false
      }
      if (!serializedPubKey || !serializedPubKey.n || !serializedPubKey.g || !serializedPubKey._n2) {
        return false
      }
      
      const pubKey = {
        n: bigInt(serializedPubKey.n),
        g: bigInt(serializedPubKey.g),
        _n2: bigInt(serializedPubKey._n2)
      }
      const messageBigInt = secureStringToBigInt(message)
      return verifySecureProof(pubKey, certificate.cipher, certificate.proof, messageBigInt)
    } catch (error) {
      return false
    }
  }
}
