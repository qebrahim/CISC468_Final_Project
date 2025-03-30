package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// GenerateKeyPair generates a new RSA key pair and saves them to the specified files.
func GenerateKeyPair(privateKeyPath, publicKeyPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Save private key
	privFile, err := os.Create(privateKeyPath)
	if err != nil {
		return err
	}
	defer privFile.Close()

	if err := pem.Encode(privFile, &pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		return err
	}

	// Save public key
	pubFile, err := os.Create(publicKeyPath)
	if err != nil {
		return err
	}
	defer pubFile.Close()

	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	if err := pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1}); err != nil {
		return err
	}

	return nil
}

// LoadPrivateKey loads a private key from a file.
func LoadPrivateKey(privateKeyPath string) (*rsa.PrivateKey, error) {
	privFile, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privFile)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// LoadPublicKey loads a public key from a file.
func LoadPublicKey(publicKeyPath string) (*rsa.PublicKey, error) {
	pubFile, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pubFile)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub.(*rsa.PublicKey), nil
}

func GenerateKey() ([]byte, error) {
	key := make([]byte, 16) // Example length for AES-128
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}
