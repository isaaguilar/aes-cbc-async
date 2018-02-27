# cbc-aes-implementation
 A exercise to create a simple encrypter with `aes-js` and `scrypt`.
 
( _linux or osx_ )
 
## Installation

```
npm install git+https://github.com/isaaguilar/aes-cbc-async.git
```
 
## Usage

- *require*

 ```
const cbc = require("aes-cbc-async")  
```

- *encrypt a string*

 ```
// encrypt
cbc.encrypt(password, plaintext, function(encryptedText){})
```

- *decrypt an encrypted string*

 ```
// decrypt
cbc.decrypt(password, encryptedText, function(plaintext){})
```
 
## Example

```
const cbc = require("aes-cbc-async")  

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
```


