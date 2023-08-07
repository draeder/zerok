const Zerok = require('../index.js')

describe('Create proof for a test message and validate it', () => {
  const zerok = new Zerok(512)
  
  let pubkey = zerok.keypair.publicKey
  let message = Math.random() // message to verify
  let proof = zerok.proof(message)
  
  it('Should return true for passed in message', () => {
    let isValid = zerok.verify(message, proof, pubkey)
    return isValid === true
  })

  it('Should return true for certificate, no message', () => {
    let isValid = zerok.verifySecret(proof, pubkey)
    return isValid === true
  })

  let corruptedMessage = message + 1
  describe('Check a bad message against proof', () => {
    it('Should return false', () => {
      let isNotValid = zerok.verify(corruptedMessage, proof, pubkey)
      return isNotValid === false
    })
  })

  describe('Change keypair and verify it against the last keypair\'s proof', () => {
    it('Should return false', () => {
      let keypair = zerok.keypair
      zerok.proof(keypair)
      zerok.newKey(32)
      let newKey = zerok.keypair
      let isNotValid = zerok.verify(newKey, proof, pubkey)
      return isNotValid === false
    })
  })

  describe('Check message against proof with new public key', () => {
    it('Should return false', () => {
      pubkey = zerok.keypair.publicKey
      let isNotValid = zerok.verify(corruptedMessage, proof, pubkey)
      return isNotValid === false
    })
  })

  describe('Check every data type works', () => {
    it('Is a string', () => {
      let proof = zerok.proof("string")
      let isValid = zerok.verify("string", proof, pubkey)
      return isValid
    })
    it('Is a number', () => {
      let proof = zerok.proof(1)
      let isValid = zerok.verify(1, proof, pubkey)
      return isValid
    })
    it('Is an object', () => {
      let proof = zerok.proof({obj: 'value'})
      let isValid = zerok.verify({obj: 'value'}, proof, pubkey)
      return isValid
    })
    it('Is an array', () => {
      let proof = zerok.proof([1,2,3])
      let isValid = zerok.verify([1,2,3], proof, pubkey)
      return isValid
    })
    it('Is a buffer', () => {
      let proof = zerok.proof(Buffer.from("string"))
      let isValid = zerok.verify(Buffer.from("string"), proof, pubkey)
      return isValid
    })
  })
})
