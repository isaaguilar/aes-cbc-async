const cbc = require("./aes-cbc.js")  

const plaintext = "Encrypt this phrase"
const password = "my secret! phrase"

// encrypt a string
cbc.encrypt(password, plaintext, function(encryptedText){
	console.log(encryptedText)
	
	// decrypt the string
	cbc.decrypt(password, encryptedText, function(decryptedText){
		console.log(decryptedText)
		console.log("is exact:", decryptedText === plaintext)
	})
})
