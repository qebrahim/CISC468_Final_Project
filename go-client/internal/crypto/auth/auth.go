package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"p2p-file-sharing/go-client/internal/crypto/keys"
	"sync"
	"time"
)

// AuthRequest contains data for the authentication handshake
type AuthRequest struct {
	PeerID    string `json:"peer_id"`
	Challenge string `json:"challenge"`
	Signature []byte `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

// AuthResponse contains the response to an authentication request
type AuthResponse struct {
	PeerID      string `json:"peer_id"`
	Challenge   string `json:"challenge"`
	Signature   []byte `json:"signature"`
	Timestamp   int64  `json:"timestamp"`
	DHPublicKey []byte `json:"dh_public_key,omitempty"` // For forward secrecy
}

// VerifiedPeer stores information about an authenticated peer
type VerifiedPeer struct {
	PeerID     string
	PublicKey  *rsa.PublicKey
	VerifiedAt time.Time
	SessionKey []byte
}

// PeerAuthentication manages peer authentication
type PeerAuthentication struct {
	PeerID     string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey

	// Mutex for thread safety
	mu sync.RWMutex

	// Map of verified peers
	VerifiedPeers map[string]*VerifiedPeer
}

// NewPeerAuthentication creates a new authentication manager
func NewPeerAuthentication(peerID string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *PeerAuthentication {
	return &PeerAuthentication{
		PeerID:        peerID,
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		VerifiedPeers: make(map[string]*VerifiedPeer),
	}
}

// InitiateAuthentication starts the authentication process with a peer
func (pa *PeerAuthentication) InitiateAuthentication() (*AuthRequest, error) {
	// Generate a random challenge
	challenge, err := keys.GenerateChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Sign the challenge with our private key
	signature, err := keys.SignMessage(pa.PrivateKey, challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to sign challenge: %w", err)
	}

	// Create authentication request
	request := &AuthRequest{
		PeerID:    pa.PeerID,
		Challenge: challenge,
		Signature: signature,
		Timestamp: time.Now().Unix(),
	}

	return request, nil
}

// VerifyAuthRequest checks if an authentication request is valid
func (pa *PeerAuthentication) VerifyAuthRequest(request *AuthRequest, peerPublicKey *rsa.PublicKey) error {
	// Verify signature
	err := keys.VerifySignature(peerPublicKey, request.Challenge, request.Signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Check timestamp (optional, to prevent replay attacks)
	now := time.Now().Unix()
	if now-request.Timestamp > 300 { // 5 minutes
		return errors.New("authentication request expired")
	}

	return nil
}

// CreateAuthResponse creates a response to an authentication request
func (pa *PeerAuthentication) CreateAuthResponse(request *AuthRequest) (*AuthResponse, error) {
	// Generate a new challenge
	challenge, err := keys.GenerateChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Sign the challenge with our private key
	signature, err := keys.SignMessage(pa.PrivateKey, challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to sign challenge: %w", err)
	}

	// Generate DH key pair for forward secrecy (simplified)
	dhKey := make([]byte, 32)
	if _, err := rand.Read(dhKey); err != nil {
		return nil, fmt.Errorf("failed to generate DH key: %w", err)
	}

	// Create authentication response
	response := &AuthResponse{
		PeerID:      pa.PeerID,
		Challenge:   challenge,
		Signature:   signature,
		Timestamp:   time.Now().Unix(),
		DHPublicKey: dhKey,
	}

	return response, nil
}

// VerifyAuthResponse checks if an authentication response is valid
func (pa *PeerAuthentication) VerifyAuthResponse(response *AuthResponse, peerPublicKey *rsa.PublicKey) error {
	// Verify signature
	err := keys.VerifySignature(peerPublicKey, response.Challenge, response.Signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Check timestamp (optional, to prevent replay attacks)
	now := time.Now().Unix()
	if now-response.Timestamp > 300 { // 5 minutes
		return errors.New("authentication response expired")
	}

	return nil
}

// AddVerifiedPeer adds a peer to the list of verified peers
func (pa *PeerAuthentication) AddVerifiedPeer(peerID string, publicKey *rsa.PublicKey, dhPublicKey []byte) {
	// In a real implementation, we would derive a shared secret from DH keys
	// For simplicity, we'll just use a hash of the DH public key as the session key

	sessionKey := sha256.Sum256(dhPublicKey)

	pa.mu.Lock()
	defer pa.mu.Unlock()

	pa.VerifiedPeers[peerID] = &VerifiedPeer{
		PeerID:     peerID,
		PublicKey:  publicKey,
		VerifiedAt: time.Now(),
		SessionKey: sessionKey[:],
	}

	fmt.Printf("🔒 Peer %s has been authenticated and added to verified peers\n", peerID)
}

// IsPeerVerified checks if a peer is verified
func (pa *PeerAuthentication) IsPeerVerified(peerID string) bool {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	_, exists := pa.VerifiedPeers[peerID]
	return exists
}

// EncryptMessage encrypts a message for a specific peer
func (pa *PeerAuthentication) EncryptMessage(peerID string, message []byte) ([]byte, error) {
	pa.mu.RLock()
	peer, exists := pa.VerifiedPeers[peerID]
	pa.mu.RUnlock()

	if !exists {
		return nil, errors.New("peer not verified")
	}

	// In a real implementation, we would use the session key for encryption
	// For simplicity, we'll use a basic XOR encryption

	sessionKey := peer.SessionKey
	encrypted := make([]byte, len(message))

	for i := 0; i < len(message); i++ {
		encrypted[i] = message[i] ^ sessionKey[i%len(sessionKey)]
	}

	// Encode with base64 for transmission
	encodedMsg := base64.StdEncoding.EncodeToString(encrypted)

	return []byte(encodedMsg), nil
}

// DecryptMessage decrypts a message from a specific peer
func (pa *PeerAuthentication) DecryptMessage(peerID string, encryptedMessage []byte) ([]byte, error) {
	pa.mu.RLock()
	peer, exists := pa.VerifiedPeers[peerID]
	pa.mu.RUnlock()

	if !exists {
		return nil, errors.New("peer not verified")
	}

	// Decode from base64
	decoded, err := base64.StdEncoding.DecodeString(string(encryptedMessage))
	if err != nil {
		return nil, fmt.Errorf("failed to decode message: %w", err)
	}

	// In a real implementation, we would use the session key for decryption
	// For simplicity, we'll use a basic XOR decryption

	sessionKey := peer.SessionKey
	decrypted := make([]byte, len(decoded))

	for i := 0; i < len(decoded); i++ {
		decrypted[i] = decoded[i] ^ sessionKey[i%len(sessionKey)]
	}

	return decrypted, nil
}

// InitiateKeyMigration starts the process of migrating to new keys
func (pa *PeerAuthentication) InitiateKeyMigration() (map[string]interface{}, error) {
	// Generate new key pair
	keyPair, err := keys.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key pair: %w", err)
	}

	// Encode public key for signing
	publicKeyBytes, err := json.Marshal(keyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Sign the new public key with the old private key
	signature, err := keys.SignMessage(pa.PrivateKey, string(publicKeyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to sign new public key: %w", err)
	}

	return map[string]interface{}{
		"new_private_key": keyPair.PrivateKey,
		"new_public_key":  keyPair.PublicKey,
		"public_key_data": publicKeyBytes,
		"signature":       signature,
	}, nil
}

// ActivateNewKeys switches to the new keys
func (pa *PeerAuthentication) ActivateNewKeys(newPrivateKey *rsa.PrivateKey, newPublicKey *rsa.PublicKey) {
	pa.PrivateKey = newPrivateKey
	pa.PublicKey = newPublicKey

	// Rotate all session keys
	pa.mu.Lock()
	defer pa.mu.Unlock()

	// In a real implementation, we would notify all peers of the key change
	// and establish new sessions with them

	fmt.Println("🔄 Keys have been migrated successfully")
}
