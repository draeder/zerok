const SecureZerok = require('../index.js')
const assert = require('assert')

describe('Secure ZeroK Implementation', () => {
  describe('Basic functionality', () => {
    it('Should create a proof and verify it successfully', () => {
      const zerok = new SecureZerok(512)
      const message = 'test message'
      const proof = zerok.proof(message)
      const isValid = zerok.verify(message, proof)
      assert.strictEqual(isValid, true)
    })
    
    it('Should reject invalid messages', () => {
      const zerok = new SecureZerok(512)
      const message = 'test message'
      const proof = zerok.proof(message)
      const isValid = zerok.verify('different message', proof)
      assert.strictEqual(isValid, false)
    })
    
    it('Should work with different data types', () => {
      const zerok = new SecureZerok(512)
      const testCases = [
        'string message',
        123456,
        { key: 'value' },
        [1, 2, 3, 4],
        true,
        null
      ]
      
      testCases.forEach(testCase => {
        const proof = zerok.proof(testCase)
        const isValid = zerok.verify(testCase, proof)
        assert.strictEqual(isValid, true, `Failed for: ${JSON.stringify(testCase)}`)
      })
    })
  })
  
  describe('Security features', () => {
    it('Should reject proofs with wrong public key', () => {
      const zerok = new SecureZerok(512)
      const message = 'test message'
      const proof = zerok.proof(message)
      
      zerok.newKey(512)
      const isValid = zerok.verify(message, proof)
      assert.strictEqual(isValid, false)
    })
    
    it('Should validate key sizes', () => {
      assert.throws(() => new SecureZerok(128), /Key size must be between 256 and 4096 bits/)
      assert.throws(() => new SecureZerok(8192), /Key size must be between 256 and 4096 bits/)
    })
    
    it('Should handle malformed proofs gracefully', () => {
      const zerok = new SecureZerok(512)
      const message = 'test message'
      const malformedProofs = [
        { cipher: '123', proof: {} },
        { cipher: '123', proof: { commitment: '1' } },
        { cipher: '123', proof: { commitment: '1', challenge: '2' } },
        null,
        undefined,
        'invalid'
      ]
      
      malformedProofs.forEach(malformedProof => {
        const isValid = zerok.verify(message, malformedProof)
        assert.strictEqual(isValid, false, `Should reject malformed proof: ${JSON.stringify(malformedProof)}`)
      })
    })
    
    it('Should handle extremely long inputs', () => {
      const zerok = new SecureZerok(512)
      const longMessage = 'a'.repeat(15000)
      assert.throws(() => zerok.proof(longMessage), /Input string too long/)
    })
  })
  
  describe('Public key serialization', () => {
    it('Should serialize and deserialize public keys', () => {
      const zerok = new SecureZerok(512)
      const message = 'test message'
      const proof = zerok.proof(message)
      const serializedPubKey = zerok.getPublicKey()
      
      const isValid = zerok.verifyWithSerializedKey(message, proof, serializedPubKey)
      assert.strictEqual(isValid, true)
    })
    
    it('Should reject verification with wrong serialized key', () => {
      const zerok1 = new SecureZerok(512)
      const zerok2 = new SecureZerok(512)
      
      const message = 'test message'
      const proof = zerok1.proof(message)
      const differentKey = zerok2.getPublicKey()
      
      const isValid = zerok1.verifyWithSerializedKey(message, proof, differentKey)
      assert.strictEqual(isValid, false)
    })
  })
  
  describe('Cross-instance verification', () => {
    it('Should verify proofs across different ZeroK instances', () => {
      const zerok1 = new SecureZerok(512)
      const zerok2 = new SecureZerok(512)
      
      const message = 'cross-instance test'
      const proof = zerok1.proof(message)
      const pubKey = zerok1.getPublicKey()
      
      const isValid = zerok2.verifyWithSerializedKey(message, proof, pubKey)
      assert.strictEqual(isValid, true)
    })
  })
  
  describe('Error handling', () => {
    it('Should handle invalid inputs gracefully', () => {
      const zerok = new SecureZerok(512)
      const invalidInputs = [
        { cipher: 'invalid', proof: { commitment: '1', challenge: '2', response: '3' } },
        { cipher: '', proof: { commitment: '1', challenge: '2', response: '3' } }
      ]
      
      invalidInputs.forEach(input => {
        const isValid = zerok.verify('test', input)
        assert.strictEqual(isValid, false)
      })
    })
  })
  
  describe('Randomness and uniqueness', () => {
    it('Should generate different proofs for the same message', () => {
      const zerok = new SecureZerok(512)
      const message = 'same message'
      const proof1 = zerok.proof(message)
      const proof2 = zerok.proof(message)
      
      // Proofs should be different due to randomness
      assert.notStrictEqual(proof1.cipher, proof2.cipher)
      assert.notStrictEqual(proof1.proof.commitment, proof2.proof.commitment)
      
      // But both should verify successfully
      assert.strictEqual(zerok.verify(message, proof1), true)
      assert.strictEqual(zerok.verify(message, proof2), true)
    })
  })
})
