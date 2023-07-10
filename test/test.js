const Zerok = require('../index.js')

describe('Create proof for a test message and validate it', () => {
  const zerok = new Zerok(512)
  
  let message = Math.random() // message to verify
  let proof = zerok.proof(message)
  
  it('Should return true', () => {
    let isValid = zerok.verify(message, proof)
    return isValid === true
  })
  
  let corruptedMessage = message + 1
  describe('Check bad message against proof', () => {
    it('Should return false', () => {
      let isNotValid = zerok.verify(corruptedMessage, proof)
      return isNotValid === false
    })
  })

  describe('Change keypair and verify it is different from the last', () => {
    it('Should return false', () => {
      let keypair = zerok.keypair
      zerok.proof(keypair)
      zerok.newKey(32)
      let newKey = zerok.keypair
      let isNotValid = zerok.verify(newKey, proof)
      return isNotValid === false
    })
  })

  describe('Check message against proof with new keypair', () => {
    it('Should return false', () => {
      let isNotValid = zerok.verify(corruptedMessage, proof)
      return isNotValid === false
    })
  })
})