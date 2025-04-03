package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Encrypt encrypts the provided data using AES-GCM with the given key
func Encrypt(data []byte, key []byte) ([]byte, error) {
	// Generate a 32-byte key if key is not 32 bytes
	if len(key) != 32 {
		key = deriveKey(key, nil, 32)
	}

	// Create a new cipher block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a nonce (Number used ONCE)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal will encrypt and authenticate the data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts the provided ciphertext using AES-GCM with the given key
func Decrypt(encryptedData []byte, key []byte) ([]byte, error) {
	// Generate a 32-byte key if key is not 32 bytes
	if len(key) != 32 {
		key = deriveKey(key, nil, 32)
	}

	// Create a new cipher block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Verify the ciphertext is at least as long as the nonce
	if len(encryptedData) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract the nonce from the ciphertext
	nonce, ciphertext := encryptedData[:gcm.NonceSize()], encryptedData[gcm.NonceSize():]

	// Decrypt and authenticate the data
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// EncryptFile encrypts a file and saves it to an output file
func EncryptFile(inputFile string, outputFile string, passphrase string) error {
	// Read input file
	plaintext, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("error reading input file: %v", err)
	}

	// Derive key from passphrase using SHA-256
	key := sha256.Sum256([]byte(passphrase))

	// Encrypt the data
	ciphertext, err := Encrypt(plaintext, key[:])
	if err != nil {
		return fmt.Errorf("error encrypting data: %v", err)
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(outputFile)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("error creating output directory: %v", err)
	}

	// Write to output file
	err = os.WriteFile(outputFile, ciphertext, 0644)
	if err != nil {
		return fmt.Errorf("error writing output file: %v", err)
	}

	return nil
}

// DecryptFile decrypts a file and saves it to an output file
func DecryptFile(inputFile string, outputFile string, passphrase string) error {
	// Read encrypted file
	ciphertext, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("error reading encrypted file: %v", err)
	}

	// Derive key from passphrase using SHA-256
	key := sha256.Sum256([]byte(passphrase))

	// Decrypt the data
	plaintext, err := Decrypt(ciphertext, key[:])
	if err != nil {
		return fmt.Errorf("error decrypting data: %v", err)
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(outputFile)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("error creating output directory: %v", err)
	}

	// Write to output file
	err = os.WriteFile(outputFile, plaintext, 0644)
	if err != nil {
		return fmt.Errorf("error writing output file: %v", err)
	}

	return nil
}

// SecureStoreFile encrypts and stores a file in a secure directory
func SecureStoreFile(inputFile string, passphrase string) (string, error) {
	// Create secure storage directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("error getting home directory: %v", err)
	}

	secureDir := filepath.Join(homeDir, ".p2p-share", "secure")
	if err := os.MkdirAll(secureDir, 0700); err != nil {
		return "", fmt.Errorf("error creating secure directory: %v", err)
	}

	// Generate a secure file name - use base name + random suffix
	baseName := filepath.Base(inputFile)
	fileExt := filepath.Ext(baseName)
	fileName := strings.TrimSuffix(baseName, fileExt)
	randomSuffix := make([]byte, 8)
	if _, err := rand.Read(randomSuffix); err != nil {
		return "", fmt.Errorf("error generating random suffix: %v", err)
	}

	secureFileName := fmt.Sprintf("%s_%s%s.enc", fileName, base64.URLEncoding.EncodeToString(randomSuffix)[:8], fileExt)
	outputFile := filepath.Join(secureDir, secureFileName)

	// Encrypt and store the file
	if err := EncryptFile(inputFile, outputFile, passphrase); err != nil {
		return "", err
	}

	return outputFile, nil
}

// SecureRetrieveFile decrypts a securely stored file and saves it to the output location
func SecureRetrieveFile(encryptedFile string, outputFile string, passphrase string) error {
	return DecryptFile(encryptedFile, outputFile, passphrase)
}

// ListSecureFiles returns a list of all encrypted files in the secure storage
func ListSecureFiles() ([]string, error) {
	// Get secure storage directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("error getting home directory: %v", err)
	}

	secureDir := filepath.Join(homeDir, ".p2p-share", "secure")

	// Check if directory exists
	if _, err := os.Stat(secureDir); os.IsNotExist(err) {
		return []string{}, nil
	}

	// List all files
	files, err := os.ReadDir(secureDir)
	if err != nil {
		return nil, fmt.Errorf("error reading secure directory: %v", err)
	}

	// Filter only .enc files
	var encryptedFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".enc") {
			encryptedFiles = append(encryptedFiles, filepath.Join(secureDir, file.Name()))
		}
	}

	return encryptedFiles, nil
}

// GenerateRandomKey generates a random cryptographic key of the specified length
func GenerateRandomKey(length int) ([]byte, error) {
	if length <= 0 {
		length = 32 // Default to 256 bits if no length specified
	}

	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// deriveKey derives a key from a password or key using HKDF-like approach
func deriveKey(secret, salt []byte, length int) []byte {
	// If no salt provided, use a fixed salt
	if salt == nil || len(salt) == 0 {
		salt = []byte("p2p-file-sharing-salt")
	}

	// Use SHA-256 for key derivation
	hash := sha256.New()
	hash.Write(secret)
	hash.Write(salt)

	// If we need a key longer than hash output, iterate
	derived := hash.Sum(nil)

	if length <= len(derived) {
		return derived[:length]
	}

	// For longer keys, keep hashing with a counter
	result := derived
	for len(result) < length {
		hash.Reset()
		hash.Write(derived)
		hash.Write([]byte{byte(len(result) / len(derived))})
		derived = hash.Sum(nil)
		result = append(result, derived...)
	}

	return result[:length]
}
