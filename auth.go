package aes256

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
)

// Generates a random string to use as an AES key. These keys need to be exactly 32 characters long and it's done as a string to be stored in plaintext.
func Random32ByteString() string {
	//needs a randomly generated 32 character string. Exactly 32 characters. The string is 22 characters, but it's encoded to 32.
	b := make([]byte, 22)
	_, err := rand.Read(b)

	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Used to encrypt a provided string using a provided key string. It's converted to a []byte within the program for processing.
func Encrypt(key string, plaintext string) string {
	// create cipher
	c, err := aes.NewCipher([]byte(key))
	fmt.Println("Checking cipher")
	if err != nil {
		log.Fatal("Failed to import decryption key.")
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		panic(err)
	}

	// encrypt
	fmt.Println("Encrypting...")
	cipherText := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	// return hex string
	return hex.EncodeToString(cipherText)
}

// Used to decrypt a provided string that was previously created with aes256.Encrypt().
// This function processes hex encoded stirngs so it should work with any secret as long as it's hex encoded.
func Decrypt(key string, encodedText string) string {
	ciphertext, _ := hex.DecodeString(encodedText)

	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal("Failed to import decryption key.")
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		panic(err)
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		log.Fatal("Failed to decrypt text. Check encryption key or regenerate credentials.")
	}
	return string(plaintext)
}
