var aesjs = require("aes-js")
var scrypt = require("scrypt-js")
var base64 = require("base-64")

var cbcEncrypt = function(key, iv, text, callback) {
  var textBytes = aesjs.utils.utf8.toBytes(text)
  var aesCbc = new aesjs.ModeOfOperation.cbc(key, iv)
  var encryptedBytes = aesCbc.encrypt(textBytes)
  var encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes)
  callback(encryptedHex, iv)
}

var cbcDecrypt = function(key, iv, encryptedHex, callback) {
  var encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex)
  var aesCbc = new aesjs.ModeOfOperation.cbc(key, iv)
  var decryptedBytes = aesCbc.decrypt(encryptedBytes)
  var decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes)
  // Un-pad
  var re = new RegExp(String.fromCharCode(15), "g")
  decryptedText = decryptedText.replace(re, "")
  callback(decryptedText)
}

var padding16 = function(s) {
  padAmount = 16 - s.length % 16
  Array.apply(null, Array(padAmount)).map(function() {
    s += String.fromCharCode(15)
  })
  return s
}

var getKey = function(password, salt, callback) {
  // passkey max 64 characters long
  var bytes = aesjs.utils.utf8.toBytes(password)
  var passBuff = new Buffer(bytes)

  var saltString = salt ? salt : Math.random().toString(36).substring(2)
  var saltBytes = aesjs.utils.utf8.toBytes(saltString)
  var saltBuff = new Buffer(saltBytes)

  var N = 1024
  var r = 8
  var p = 1
  var dkLen = 32

  var encryptedHex = ""
  scrypt(passBuff, saltBuff, N, r, p, dkLen, function(error, progress, key) {
    callback(error, progress, key, saltString)
  })
}

var getIv = function(callback) {
  var saltString1 = Math.random().toString(36).substring(2)
  var saltBytes1 = aesjs.utils.utf8.toBytes(saltString1)
  var saltBuff1 = new Buffer(saltBytes1)

  var saltString2 = Math.random().toString(36).substring(2)
  var saltBytes2 = aesjs.utils.utf8.toBytes(saltString2)
  var saltBuff2 = new Buffer(saltBytes2)

  var N = 1024
  var r = 8
  var p = 1
  var dkLen = 16

  var encryptedHex = ""
  scrypt(saltBuff1, saltBuff2, N, r, p, dkLen, function(error, progress, key) {
    callback(error, progress, key)
  })
}

var encrypt = function(password, text, callback) {
  text = padding16(text)
  getKey(password, null, function(error, progress, key, salt) {
    if (key) {
      getIv(function(error, progress, iv) {
        if (iv) {
          cbcEncrypt(key, iv, text, function(hex, iv) {
            var ivHex = aesjs.utils.hex.fromBytes(iv)
            var encryptedHexWithSalt = salt + "+" + ivHex + ":" + hex
            // encode as base64
            callback(base64.encode(encryptedHexWithSalt))
          })
        }
      })
    }
  })
}

var decrypt = function(password, encodedSaltedHex, callback) {
  var saltedHex = base64.decode(encodedSaltedHex)
  var hex = saltedHex.split(":")
  var saltiv = hex[0]

  var encryptedHex = hex[1]
  var salt = saltiv.split("+")[0]
  var iv = aesjs.utils.hex.toBytes(saltiv.split("+")[1])

  getKey(password, salt, function(error, progress, key) {
    if (key) {
      cbcDecrypt(key, iv, encryptedHex, function(decryptedText) {
        callback(decryptedText)
      })
    }
  })
}

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt
}
