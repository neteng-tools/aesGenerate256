package aes256

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Generates a random string to use as an AES key. These keys need to be exactly 32 characters long and it's done as a string to be stored in plaintext.
func Random32ByteString() string {
	//needs a randomly generated 32 character string. Exactly 32 characters. The string is 22 characters, but it's encoded to 32.
	b := make([]byte, 22)
	// b is overriden by rand.Read and an error causes a panic, no need to do anything with the returned data.
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// Used to encrypt a provided string using a provided key string. It's converted to a []byte within the program for processing.
func Encrypt(key string, plaintext string) (string, error) {
	// create cipher
	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("failed to import decryption key: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", fmt.Errorf("failed to generate block cipher: %w", err)

	}

	nonce := make([]byte, gcm.NonceSize())
	// nonce is overriden by rand.Read and an error causes a panic, no need to do anything with the returned data.
	rand.Read(nonce)
	cipherText := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	// return hex string
	return hex.EncodeToString(cipherText), nil
}

// Used to decrypt a provided string that was previously created with aes256.Encrypt().
// This function processes hex encoded stirngs so it should work with any secret as long as it's hex encoded.
func Decrypt(key string, encodedText string) (string, error) {
	ciphertext, _ := hex.DecodeString(encodedText)

	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("failed to import decryption key: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", fmt.Errorf("failed to generate block cipher: %w", err)
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		return "", fmt.Errorf("Failed to decrypt text. Check encryption key or regenerate credentials: %w", err)
	}
	return string(plaintext), nil
}
