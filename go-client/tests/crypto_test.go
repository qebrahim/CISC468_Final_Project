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
