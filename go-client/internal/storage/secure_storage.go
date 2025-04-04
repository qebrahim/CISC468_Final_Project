package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SecureStorage manages the secure storage of files
type SecureStorage struct {
	StorageDir string
	KeysDir    string
}

// NewSecureStorage creates a new secure storage manager
func NewSecureStorage() (*SecureStorage, error) {
	// Get home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("error getting home directory: %v", err)
	}

	// Create storage directories - use 'secure' instead of 'shared' for encrypted files
	storageDir := filepath.Join(homeDir, ".p2p-share", "secure")
	keysDir := filepath.Join(homeDir, ".p2p-share", "keys", "secure")

	// Ensure directories exist
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return nil, fmt.Errorf("error creating secure storage directory: %v", err)
	}

	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("error creating secure keys directory: %v", err)
	}

	return &SecureStorage{
		StorageDir: storageDir,
		KeysDir:    keysDir,
	}, nil
}

// Modify the SecureStoreFile function in secure_storage.go to save the key as a base64 encoded string
func (s *SecureStorage) SecureStoreFile(inputFile string, passphrase string) (string, error) {
	// Generate a unique ID for the file (timestamp + 8 random bytes)
	randomID := make([]byte, 8)
	_, err := rand.Read(randomID)
	if err != nil {
		return "", fmt.Errorf("error generating random ID: %v", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	uniqueID := fmt.Sprintf("%s_%s", timestamp, base64.URLEncoding.EncodeToString(randomID)[:8])

	// Get the original filename
	originalName := filepath.Base(inputFile)
	secureFileName := fmt.Sprintf("%s_%s.enc", strings.TrimSuffix(originalName, filepath.Ext(originalName)), uniqueID)
	outputPath := filepath.Join(s.StorageDir, secureFileName)

	// Read the file
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return "", fmt.Errorf("error reading file: %v", err)
	}

	// Derive encryption key from passphrase
	key := deriveKey([]byte(passphrase), nil, 32)

	// Encrypt the data
	encryptedData, err := encryptData(data, key)
	if err != nil {
		return "", fmt.Errorf("error encrypting data: %v", err)
	}

	// Create directory if needed
	if err := os.MkdirAll(s.StorageDir, 0700); err != nil {
		return "", fmt.Errorf("error creating secure directory: %v", err)
	}

	// Write encrypted data to output file
	err = ioutil.WriteFile(outputPath, encryptedData, 0600)
	if err != nil {
		return "", fmt.Errorf("error writing encrypted file: %v", err)
	}

	// If passphrase was auto-generated, store it in a key file
	if passphrase == "" {
		// Generate a random passphrase
		passphraseBytes := make([]byte, 16)
		_, err := rand.Read(passphraseBytes)
		if err != nil {
			return "", fmt.Errorf("error generating passphrase: %v", err)
		}
		passphrase = base64.URLEncoding.EncodeToString(passphraseBytes)
	}

	// Store the passphrase as a base64 encoded string
	keyPath := filepath.Join(s.KeysDir, secureFileName+".key")
	err = ioutil.WriteFile(keyPath, []byte(passphrase), 0600)
	if err != nil {
		return "", fmt.Errorf("error writing key file: %v", err)
	}

	// Return the path to the encrypted file
	return outputPath, nil
}

// Correspondingly, modify the SecureRetrieveFile function
func (s *SecureStorage) SecureRetrieveFile(encryptedFilePath, outputPath string, passphrase string) error {
	// If no passphrase provided, try to load from key file
	if passphrase == "" {
		fileName := filepath.Base(encryptedFilePath)
		keyPath := filepath.Join(s.KeysDir, fileName+".key")

		keyData, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("error reading key file: %v", err)
		}
		passphrase = string(keyData)
	}

	// Read encrypted file
	encryptedData, err := ioutil.ReadFile(encryptedFilePath)
	if err != nil {
		return fmt.Errorf("error reading encrypted file: %v", err)
	}

	// Derive key from passphrase
	key := deriveKey([]byte(passphrase), nil, 32)

	// Decrypt the data
	decryptedData, err := decryptData(encryptedData, key)
	if err != nil {
		return fmt.Errorf("error decrypting data: %v", err)
	}

	// Write decrypted data to output file
	err = ioutil.WriteFile(outputPath, decryptedData, 0644)
	if err != nil {
		return fmt.Errorf("error writing decrypted file: %v", err)
	}

	return nil
}

// ListSecureFiles lists all securely stored files
func (s *SecureStorage) ListSecureFiles() ([]string, error) {
	files, err := ioutil.ReadDir(s.StorageDir)
	if err != nil {
		return nil, fmt.Errorf("error reading secure storage directory: %v", err)
	}

	var secureFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".enc") {
			secureFiles = append(secureFiles, filepath.Join(s.StorageDir, file.Name()))
		}
	}

	return secureFiles, nil
}

// DeleteSecureFile deletes a securely stored file and its key file
func (s *SecureStorage) DeleteSecureFile(filePath string) error {
	// Delete the encrypted file
	err := os.Remove(filePath)
	if err != nil {
		return fmt.Errorf("error deleting encrypted file: %v", err)
	}

	// Try to delete the key file if it exists
	fileName := filepath.Base(filePath)
	keyPath := filepath.Join(s.KeysDir, fileName+".key")

	// Key file might not exist (user-provided passphrase), so ignore errors
	os.Remove(keyPath)

	return nil
}

// encryptData encrypts data using AES-GCM
func encryptData(data []byte, key []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptData decrypts data using AES-GCM
func decryptData(data []byte, key []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Verify the data is at least as long as the nonce
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract the nonce from the beginning of the data
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// deriveKey derives a key from a password using SHA-256
func deriveKey(password, salt []byte, keyLen int) []byte {
	if salt == nil {
		salt = []byte("p2p-file-sharing-salt")
	}

	// Use SHA-256 for key derivation
	hash := sha256.New()
	hash.Write(password)
	hash.Write(salt)

	// Derive the key
	key := hash.Sum(nil)

	// If we need a key shorter than the hash output, truncate
	if keyLen < len(key) {
		key = key[:keyLen]
	}

	// If we need a longer key, iterate the hash function
	if keyLen > len(key) {
		newKey := make([]byte, keyLen)
		copy(newKey, key)

		for i := len(key); i < keyLen; {
			hash.Reset()
			hash.Write(key)
			hash.Write([]byte{byte(i / len(key))})

			additionalKey := hash.Sum(nil)
			copyLen := min(len(additionalKey), keyLen-i)
			copy(newKey[i:], additionalKey[:copyLen])

			i += copyLen
		}

		key = newKey
	}

	return key
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// This function handles on-demand file decryption for temporary access
func (s *SecureStorage) TemporaryDecrypt(encryptedFilePath string, outputPath string, passphrase string, timeout time.Duration) error {
	// Decrypt the file
	err := s.SecureRetrieveFile(encryptedFilePath, outputPath, passphrase)
	if err != nil {
		return fmt.Errorf("error decrypting file: %v", err)
	}

	// Set up automatic deletion after timeout
	go func() {
		time.Sleep(timeout)
		// Delete the temporary decrypted file
		err := os.Remove(outputPath)
		if err != nil {
			fmt.Printf("Warning: Failed to remove temporary decrypted file: %v\n", err)
		} else {
			fmt.Printf("Temporary decrypted file removed after timeout: %s\n", outputPath)
		}
	}()

	return nil
}
