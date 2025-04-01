package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// FileEncryption provides functionality for encrypting and decrypting files
// using a session key, matching the Python implementation
type FileEncryption struct {
	key []byte
}

// NewFileEncryption creates a new file encryption instance with a derived key
func NewFileEncryption(sessionKey []byte) *FileEncryption {
	// Derive a cryptographic key from the session key using PBKDF2
	// to match Python's Fernet key derivation
	derivedKey := deriveKey(sessionKey)

	return &FileEncryption{
		key: derivedKey,
	}
}

// deriveKey uses PBKDF2 to derive a key compatible with Fernet
// from the raw session key
func deriveKey(sessionKey []byte) []byte {
	// These parameters match the Python implementation
	salt := []byte("file_transfer_salt")
	iterations := 100000
	keyLength := 32

	// Generate the key using PBKDF2
	derivedKey := pbkdf2.Key(sessionKey, salt, iterations, keyLength, sha256.New)

	// Base64-encode the key to match Python's Fernet requirements
	encoded := base64.URLEncoding.EncodeToString(derivedKey)

	// Fernet requires the key to be 32 bytes
	return []byte(encoded)
}

// EncryptFileData encrypts data using AES-GCM with a random nonce
func (fe *FileEncryption) EncryptFileData(data []byte) ([]byte, error) {
	// Create AES cipher block
	block, err := aes.NewCipher(fe.key[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	sealed := gcm.Seal(nonce, nonce, data, nil)
	return sealed, nil
}

// DecryptFileData decrypts data that was encrypted using EncryptFileData
func (fe *FileEncryption) DecryptFileData(encryptedData []byte) ([]byte, error) {
	// Create AES cipher block
	block, err := aes.NewCipher(fe.key[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
