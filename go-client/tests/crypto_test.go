package tests

import (
	"p2p-file-sharing/go-client/internal/crypto"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	plaintext := []byte("Hello, World!")
	key := []byte("examplekey12345") // Example key, should be securely generated

	ciphertext, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decryptedText, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decryptedText) != string(plaintext) {
		t.Errorf("Decrypted text does not match original. Got: %s, Want: %s", decryptedText, plaintext)
	}
}

func TestKeyGeneration(t *testing.T) {
	key, error := crypto.GenerateKey() // Assuming GenerateKey is a function that generates a key
	print(error)
	if len(key) != 16 { // Example length for AES-128
		t.Errorf("Generated key length is incorrect. Got: %d, Want: 16", len(key))
	}
}
