package session

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"crypto/ecdh"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// SessionLifetime defines how long a session is valid (1 hour)
	SessionLifetime = 3600 * time.Second

	// KeySize for NaCl secretbox
	KeySize = 32

	// NonceSize for NaCl secretbox
	NonceSize = 24
)

// Session represents a secure communication session with a peer
type Session struct {
	PrivateKey *ecdh.PrivateKey // ECDH private key
	PublicKey  *ecdh.PublicKey  // ECDH public key
	PeerKey    *ecdh.PublicKey  // Peer's ECDH public key
	SharedKey  []byte           // Derived shared secret
	CreatedAt  time.Time        // When this session was created
	LastUsed   time.Time        // When this session was last used
}

// SessionManager manages secure communication sessions with peers
type SessionManager struct {
	mu       sync.RWMutex
	curve    elliptic.Curve
	sessions map[string]*Session // Map of peer IDs to sessions
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		curve:    elliptic.P256(), // Use P-256 curve for ECDH
		sessions: make(map[string]*Session),
	}
}

// CreateSession initializes a new session for a peer
func (sm *SessionManager) CreateSession(peerID string) ([]byte, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Generate ECDH keypair
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDH key: %w", err)
	}

	publicKey := privateKey.PublicKey()

	// Store session information
	sm.sessions[peerID] = &Session{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
	}

	// Return serialized public key
	return publicKey.Bytes(), nil
}

// CompleteSession finalizes a session with a peer's public key
func (sm *SessionManager) CompleteSession(peerID string, peerPublicKeyBytes []byte) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Find existing session
	session, exists := sm.sessions[peerID]
	if !exists {
		return errors.New("no session initiated for peer")
	}

	// Parse peer's public key
	peerPublicKey, err := ecdh.P256().NewPublicKey(peerPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid peer public key: %w", err)
	}

	// Compute shared secret
	sharedSecret, err := session.PrivateKey.ECDH(peerPublicKey)
	if err != nil {
		return fmt.Errorf("ECDH key exchange failed: %w", err)
	}

	// Derive encryption key using HKDF (similar to Python)
	reader := hkdf.New(sha256.New, sharedSecret, nil, []byte("handshake data"))
	derivedKey := make([]byte, KeySize)
	if _, err := reader.Read(derivedKey); err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}

	// Update session
	session.PeerKey = peerPublicKey
	session.SharedKey = derivedKey
	session.LastUsed = time.Now()

	return nil
}

// EncryptMessage encrypts a message for a specific peer
func (sm *SessionManager) EncryptMessage(peerID string, message []byte) ([]byte, error) {
	sm.mu.RLock()
	session, valid := sm.isSessionValid(peerID)
	sm.mu.RUnlock()

	if !valid || session == nil {
		return nil, errors.New("no valid session for peer")
	}

	sm.mu.Lock()
	session.LastUsed = time.Now()
	sm.mu.Unlock()

	// Generate random nonce
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Copy shared key to fixed-size array
	var key [KeySize]byte
	copy(key[:], session.SharedKey)

	// Encrypt message
	encrypted := secretbox.Seal(nonce[:], message, &nonce, &key)
	return encrypted, nil
}

// DecryptMessage decrypts a message from a specific peer
func (sm *SessionManager) DecryptMessage(peerID string, encryptedMessage []byte) ([]byte, error) {
	sm.mu.RLock()
	session, valid := sm.isSessionValid(peerID)
	sm.mu.RUnlock()

	if !valid || session == nil {
		return nil, errors.New("no valid session for peer")
	}

	sm.mu.Lock()
	session.LastUsed = time.Now()
	sm.mu.Unlock()

	// Ensure message is long enough
	if len(encryptedMessage) < NonceSize {
		return nil, errors.New("encrypted message too short")
	}

	// Extract nonce and ciphertext
	var nonce [NonceSize]byte
	copy(nonce[:], encryptedMessage[:NonceSize])
	ciphertext := encryptedMessage[NonceSize:]

	// Copy shared key to fixed-size array
	var key [KeySize]byte
	copy(key[:], session.SharedKey)

	// Decrypt message
	message, ok := secretbox.Open(nil, ciphertext, &nonce, &key)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return message, nil
}

// RotateSession creates a new session for an existing peer
func (sm *SessionManager) RotateSession(peerID string) ([]byte, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check if session exists
	_, exists := sm.sessions[peerID]
	if !exists {
		return nil, errors.New("no existing session for peer")
	}

	// Generate new ECDH keypair
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDH key: %w", err)
	}

	publicKey := privateKey.PublicKey()

	// Replace session
	sm.sessions[peerID] = &Session{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
	}

	// Return serialized public key
	return publicKey.Bytes(), nil
}

// isSessionValid checks if a session is valid and not expired
func (sm *SessionManager) isSessionValid(peerID string) (*Session, bool) {
	session, exists := sm.sessions[peerID]
	if !exists {
		return nil, false
	}

	// Check if session has expired
	if time.Since(session.CreatedAt) > SessionLifetime {
		delete(sm.sessions, peerID)
		return nil, false
	}

	// Check if session is complete
	if session.SharedKey == nil {
		return nil, false
	}

	return session, true
}

// GetSessionInfo returns information about a peer's session
func (sm *SessionManager) GetSessionInfo(peerID string) (time.Time, time.Time, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, valid := sm.isSessionValid(peerID)
	if !valid || session == nil {
		return time.Time{}, time.Time{}, errors.New("no valid session for peer")
	}

	return session.CreatedAt, session.LastUsed, nil
}
