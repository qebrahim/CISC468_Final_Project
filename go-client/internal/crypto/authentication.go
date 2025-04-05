package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PendingChallenge represents a challenge sent to a peer
type PendingChallenge struct {
	PeerID    string
	Challenge []byte
	Timestamp float64
}

// PeerAuthentication handles authentication between peers
type PeerAuthentication struct {
	PeerID            string
	ContactManager    *ContactManager
	PrivateKey        *rsa.PrivateKey
	PublicKey         *rsa.PublicKey
	PublicKeyPEM      string
	PrivateKeyPath    string
	PublicKeyPath     string
	PendingChallenges map[string]PendingChallenge
}

// NewPeerAuthentication creates a new PeerAuthentication instance
func NewPeerAuthentication(peerID string, contactManager *ContactManager) (*PeerAuthentication, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("error getting home directory: %v", err)
	}

	storagePath := filepath.Join(homeDir, ".p2p-share", "keys")
	err = os.MkdirAll(storagePath, 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating keys directory: %v", err)
	}

	privateKeyPath := filepath.Join(storagePath, "private.pem")
	publicKeyPath := filepath.Join(storagePath, "public.pem")

	auth := &PeerAuthentication{
		PeerID:            peerID,
		ContactManager:    contactManager,
		PrivateKeyPath:    privateKeyPath,
		PublicKeyPath:     publicKeyPath,
		PendingChallenges: make(map[string]PendingChallenge),
	}

	// Load keys
	err = auth.LoadKeys()
	if err != nil {
		return nil, fmt.Errorf("error loading keys: %v", err)
	}

	return auth, nil
}

// LoadKeys loads the RSA key pair
func (pa *PeerAuthentication) LoadKeys() error {
	// Load private key
	privateKey, err := LoadPrivateKey(pa.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load private key: %v", err)
	}
	pa.PrivateKey = privateKey

	// Load public key
	publicKey, err := LoadPublicKey(pa.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load public key: %v", err)
	}
	pa.PublicKey = publicKey

	// Export public key in PEM format for sharing
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	pubKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}))
	pa.PublicKeyPEM = pubKeyPEM

	fmt.Println("Successfully loaded key pair")
	return nil
}

// GetPublicKeyPEM returns the PEM encoded public key
func (pa *PeerAuthentication) GetPublicKeyPEM() string {
	return pa.PublicKeyPEM
}

// CreateChallenge creates a new authentication challenge for a peer
// In internal/crypto/authentication.go, modify the CreateChallenge method:

func (pa *PeerAuthentication) CreateChallenge(peerID string) (string, string, error) {
	// Generate more unique challenge ID
	challengeIDBytes := make([]byte, 16) // Increase from 8 to 16
	_, err := rand.Read(challengeIDBytes)
	if err != nil {
		return "", "", fmt.Errorf("error generating challenge ID: %v", err)
	}
	// Use timestamped ID to reduce collision chance
	timestampPrefix := fmt.Sprintf("%d_", time.Now().UnixNano())
	challengeIDStr := timestampPrefix + fmt.Sprintf("%x", challengeIDBytes)

	// Generate random 32-byte challenge
	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	if err != nil {
		return "", "", fmt.Errorf("error generating challenge: %v", err)
	}

	// Store challenge for later verification with more data
	pa.PendingChallenges[challengeIDStr] = PendingChallenge{
		PeerID:    peerID,
		Challenge: challenge,
		Timestamp: float64(time.Now().Unix()),
	}

	// Clean up old challenges
	pa.CleanupChallenges()

	// Return base64 encoded challenge
	challengeB64 := base64.StdEncoding.EncodeToString(challenge)
	return challengeIDStr, challengeB64, nil
}

// CleanupChallenges removes challenges older than 5 minutes
func (pa *PeerAuthentication) CleanupChallenges() {
	currentTime := float64(time.Now().Unix())
	var expiredChallenges []string

	for challengeID, data := range pa.PendingChallenges {
		if currentTime-data.Timestamp > 300 { // 5 minutes
			expiredChallenges = append(expiredChallenges, challengeID)
		}
	}

	for _, challengeID := range expiredChallenges {
		delete(pa.PendingChallenges, challengeID)
	}
}

// SignChallenge signs a challenge from another peer
func (pa *PeerAuthentication) SignChallenge(challengeB64 string) (string, error) {
	// Decode the challenge
	challenge, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil {
		return "", fmt.Errorf("error decoding challenge: %v", err)
	}

	// Hash the challenge
	hashed := sha256.Sum256(challenge)

	// Sign the hash
	signature, err := rsa.SignPSS(rand.Reader, pa.PrivateKey, crypto.SHA256, hashed[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	if err != nil {
		return "", fmt.Errorf("error signing challenge: %v", err)
	}

	// Return base64 encoded signature
	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	return signatureB64, nil
}

// VerifySignature verifies a peer's signature of our challenge
func (pa *PeerAuthentication) VerifySignature(peerID, challengeID, signatureB64 string, publicKeyPEM string) (bool, error) {
	// Get the challenge
	challengeData, exists := pa.PendingChallenges[challengeID]
	if !exists {
		return false, fmt.Errorf("challenge %s not found or expired", challengeID)
	}

	if challengeData.PeerID != peerID {
		return false, fmt.Errorf("challenge was not created for peer %s", peerID)
	}

	var block *pem.Block
	var pubInterface interface{}
	var err error

	// If a public key PEM is provided directly, use it
	if publicKeyPEM != "" {
		block, _ = pem.Decode([]byte(publicKeyPEM))
		if block == nil || block.Type != "PUBLIC KEY" {
			return false, fmt.Errorf("failed to decode PEM block containing public key")
		}

		pubInterface, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return false, fmt.Errorf("failed to parse public key: %v", err)
		}

		pubKey, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("not an RSA public key")
		}

		// Decode the signature
		signature, err := base64.StdEncoding.DecodeString(signatureB64)
		if err != nil {
			return false, fmt.Errorf("error decoding signature: %v", err)
		}

		// Hash the challenge
		hashed := sha256.Sum256(challengeData.Challenge)

		// Verify the signature
		err = rsa.VerifyPSS(pubKey, crypto.SHA256, hashed[:], signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		})
		if err != nil {
			return false, fmt.Errorf("invalid signature: %v", err)
		}
	} else {
		// Otherwise, try to get the public key from the contact manager
		contact, exists := pa.ContactManager.GetTrustedContact(peerID)
		if !exists {
			return false, fmt.Errorf("no public key found for peer %s", peerID)
		}

		// Load the peer's public key
		block, _ = pem.Decode([]byte(contact.PublicKey))
		if block == nil || block.Type != "PUBLIC KEY" {
			return false, fmt.Errorf("failed to decode PEM block containing public key")
		}

		pubInterface, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return false, fmt.Errorf("failed to parse public key: %v", err)
		}

		pubKey, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("not an RSA public key")
		}

		// Decode the signature
		signature, err := base64.StdEncoding.DecodeString(signatureB64)
		if err != nil {
			return false, fmt.Errorf("error decoding signature: %v", err)
		}

		// Hash the challenge
		hashed := sha256.Sum256(challengeData.Challenge)

		// Verify the signature
		err = rsa.VerifyPSS(pubKey, crypto.SHA256, hashed[:], signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		})
		if err != nil {
			return false, fmt.Errorf("invalid signature: %v", err)
		}
	}

	// Signature is valid
	fmt.Printf("Successfully verified signature from peer %s\n", peerID)

	// Clean up the challenge
	delete(pa.PendingChallenges, challengeID)

	// Update last seen time
	pa.ContactManager.UpdateLastSeen(peerID)

	return true, nil
}

// LoadPeerPublicKey loads and parses a peer's public key from PEM format
func (pa *PeerAuthentication) LoadPeerPublicKey(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return pubKey, nil
}

// Add this function to a suitable file in the crypto package, e.g., authentication.go
func GetPeerID() string {
	if authentication == nil {
		return ""
	}
	return authentication.PeerID
}
