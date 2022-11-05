const keccak256 = require("keccak256")
const BN = require('bn.js')



// string to 32 bits hexadecimals
const toBytes32 = value => {
    return "0x" + keccak256(value).toString("hex")
}


// string to hexadecimals 32 * n length 
const toDataBytes = value => {
    const bytesArray = value.split("").map(el => keccak256(el).toString("hex"))
    return "0x" + bytesArray.join("")
}


// function to drop 0x from a string value
const drop0x = val => {
    const valSplitedArray = val.split("0x")
    return valSplitedArray[valSplitedArray.length - 1]
}


// function to add 0x from a string value
const add0x = val => {
    return "0x" + val
}


// encrypt decrypt function
const encryptDecrypt = (_data, _key) => {
    try {
        // drop 0x to _data
        const dataWithout0x = drop0x(_data)

        // length of bytes
        const length = dataWithout0x.length / 2

        // result start from 0x
        let result = "0x"

        // index to look at start from 2
        let startFrom = 2

        for (let i = 0; i < length; i += 32) {

            // hash that concatenat key + i
            const hash = add0x(keccak256(_key + i.toString()).toString("hex"))

            // byte extraction from byte data at index startFrom
            const chunk = add0x(_data.slice(startFrom, startFrom + 64))

            // binary value of hash value
            const hashBinary = new BN(parseInt(hash).toString(2), 2)

            // binary value of chunk value
            const chunkBinary = new BN(parseInt(chunk).toString(2), 2)

            // xor comparison
            const hashedBinaryValue = hashBinary.xor(chunkBinary)

            // hashedBinaryValue to 32 bytes value
            const valueToReturn = keccak256(hashedBinaryValue.toString()).toString("hex")

            // result concatenation
            result += valueToReturn

            // increase start index by 64 ===> 64 / 2 = 32 bytes
            startFrom += 64
        }

        return result

    } catch (e) {
        console.log(e.message)
        process.exit()
    }

}

module.exports = {
    encryptDecrypt,
    toDataBytes,
    toBytes32
}