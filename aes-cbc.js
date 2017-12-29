const aesjs = require("aes-js")
const scrypt = require("scrypt-js")
const base64 = require("base-64")

const cbcEncrypt = (key, iv, text, callback) => {
  const textBytes = aesjs.utils.utf8.toBytes(text)
  const aesCbc = new aesjs.ModeOfOperation.cbc(key, iv)
  const encryptedBytes = aesCbc.encrypt(textBytes)
  const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes)
  callback(encryptedHex, iv)
}

const cbcDecrypt = (key, iv, encryptedHex, callback) => {
  const encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex)
  const aesCbc = new aesjs.ModeOfOperation.cbc(key, iv)
  const decryptedBytes = aesCbc.decrypt(encryptedBytes)
  let decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes)
  // Un-pad
  const re = new RegExp(String.fromCharCode(15), "g")
  decryptedText = decryptedText.replace(re, "")
  callback(decryptedText)
}

const padding16 = s => {
  padAmount = 16 - s.length % 16
  Array.apply(null, Array(padAmount)).map(() => {
    s += String.fromCharCode(15)
  })
  return s
}

const getKey = (password, salt, callback) => {
  // passkey max 64 characters long
  const bytes = aesjs.utils.utf8.toBytes(password)
  const passBuff = new Buffer(bytes)

  const saltString = salt ? salt : Math.random().toString(36).substring(2)
  const saltBytes = aesjs.utils.utf8.toBytes(saltString)
  const saltBuff = new Buffer(saltBytes)

  const N = 1024
  const r = 8
  const p = 1
  const dkLen = 32

  let encryptedHex = ""
  scrypt(passBuff, saltBuff, N, r, p, dkLen, function(error, progress, key) {
    callback(error, progress, key, saltString)
  })
}

const getIv = callback => {
  const saltString1 = Math.random().toString(36).substring(2)
  const saltBytes1 = aesjs.utils.utf8.toBytes(saltString1)
  const saltBuff1 = new Buffer(saltBytes1)

  const saltString2 = Math.random().toString(36).substring(2)
  const saltBytes2 = aesjs.utils.utf8.toBytes(saltString2)
  const saltBuff2 = new Buffer(saltBytes2)

  const N = 1024
  const r = 8
  const p = 1
  const dkLen = 16

  let encryptedHex = ""
  scrypt(saltBuff1, saltBuff2, N, r, p, dkLen, function(error, progress, key) {
    callback(error, progress, key)
  })
}

const encrypt = (password, text, callback) => {
  text = padding16(text)
  getKey(password, null, (error, progress, key, salt) => {
    if (key) {
      getIv((error, progress, iv) => {
        if (iv) {
          cbcEncrypt(key, iv, text, (hex, iv) => {
            const ivHex = aesjs.utils.hex.fromBytes(iv)
            const encryptedHexWithSalt = salt + "+" + ivHex + ":" + hex
            // encode as base64
            callback(base64.encode(encryptedHexWithSalt))
          })
        }
      })
    }
  })
}

const decrypt = (password, encodedSaltedHex, callback) => {
  const saltedHex = base64.decode(encodedSaltedHex)
  const hex = saltedHex.split(":")
  const saltiv = hex[0]

  const encryptedHex = hex[1]
  const salt = saltiv.split("+")[0]
  const iv = aesjs.utils.hex.toBytes(saltiv.split("+")[1])

  getKey(password, salt, (error, progress, key) => {
    if (key) {
      cbcDecrypt(key, iv, encryptedHex, (decryptedText) => {
        callback(decryptedText)
      })
    }
  })
}

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt
}
