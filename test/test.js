const Zerok = require('../index.js')

describe('Create proof for a test message and validate it', () => {
  const zerok = new Zerok(512)
  
  let pubkey = zerok.keypair.publicKey
  let message = Math.random() // message to verify
  let proof = zerok.proof(message)
  
  it('Should return true', () => {
    let isValid = zerok.verify(message, proof, pubkey)
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
})
