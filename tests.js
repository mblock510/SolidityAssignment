const assert = require('chai').assert
const encryptDecrypt = require("./EncryptDecrypt")

// values to assign
const data = encryptDecrypt.toDataBytes("Blockchain is super cool")
const key = encryptDecrypt.toBytes32("MyPassword")


describe("UNITESTS VALUES LENGTH.", async() => {
    let encrytedValue
    before(() => {
        encrytedValue = encryptDecrypt.encryptDecrypt(data, key)
    })
    after(() => process.exit())

    it('MUST HAVE SAME STRING LENGTH', () => {
        assert.equal(data.length, encrytedValue.length)
    })

    it('MUST HAVE DIFFERENT STRING VALUES', () => {
        assert.notEqual(data, encrytedValue)
    })
})