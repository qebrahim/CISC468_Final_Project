package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// SecureChannel implements encrypted communication using ECDHE for forward secrecy
// SecureChannel implements encrypted communication using ECDHE for forward secrecy
type SecureChannel struct {
	PeerID         string
	Conn           net.Conn
	IsInitiator    bool
	Established    bool
	SessionID      string
	PrivateKey     *ecdh.PrivateKey // Switch back to ECDH for Python compatibility
	PeerPublicKey  *ecdh.PublicKey  // Switch back to ECDH for Python compatibility
	EncryptionKey  []byte
	DecryptionKey  []byte
	SendCounter    uint32
	ReceiveCounter uint32
	mutex          sync.Mutex
}

// Global registry of secure channels
var (
	secureChannels     = make(map[string]*SecureChannel)
	secureChannelMutex sync.RWMutex
)

// In NewSecureChannel function in secure_channel.go
// NewSecureChannel creates a new secure channel
func NewSecureChannel(peerID string, conn net.Conn, isInitiator bool) (*SecureChannel, error) {
	// Generate key pair using ECDH for compatibility with Python's cryptography
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("error generating ephemeral key: %v", err)
	}

	sc := &SecureChannel{
		PeerID:      peerID,
		Conn:        conn,
		IsInitiator: isInitiator,
		PrivateKey:  privateKey,
		Established: false,
		SessionID:   "",
		mutex:       sync.Mutex{},
	}

	return sc, nil
}

// InitiateKeyExchange starts the key exchange process
func (sc *SecureChannel) InitiateKeyExchange() error {
	// Generate a unique session ID
	sessionIDBytes := make([]byte, 8)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		return fmt.Errorf("error generating session ID: %v", err)
	}
	sc.SessionID = fmt.Sprintf("%x", sessionIDBytes)

	// Format public key in a way that's compatible with Python's cryptography library
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(sc.PrivateKey.PublicKey())
	if err != nil {
		return fmt.Errorf("error marshaling public key: %v", err)
	}

	// Encode as PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Create key exchange message
	keyExchangeMsg := map[string]interface{}{
		"peer_id":    sc.PeerID,
		"session_id": sc.SessionID,
		"public_key": string(keyPEM),
	}

	// Debug log
	fmt.Printf("Initiating key exchange with peer %s\n", sc.PeerID)
	fmt.Printf("Our public key (PEM format): %s...\n", string(keyPEM)[:60])

	// Encode to JSON
	msgBytes, err := json.Marshal(keyExchangeMsg)
	if err != nil {
		return fmt.Errorf("error encoding key exchange message: %v", err)
	}

	// Send message
	_, err = sc.Conn.Write([]byte(fmt.Sprintf("SECURE:EXCHANGE:%s", string(msgBytes))))
	if err != nil {
		return fmt.Errorf("error sending key exchange: %v", err)
	}

	fmt.Printf("Sent key exchange request to peer %s\n", sc.PeerID)
	return nil
}

func (sc *SecureChannel) HandleKeyExchange(exchangeData map[string]interface{}) error {
	// Extract peer ID, session ID, and public key
	peerID, ok := exchangeData["peer_id"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid peer_id in key exchange")
	}

	sessionID, ok := exchangeData["session_id"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid session_id in key exchange")
	}

	peerPublicKeyPEM, ok := exchangeData["public_key"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid public_key in key exchange")
	}

	// Debug log
	fmt.Printf("Processing key exchange from peer %s with session %s\n", peerID, sessionID)
	fmt.Printf("Received peer public key: %s...\n", peerPublicKeyPEM[:60])

	// Store session ID
	sc.SessionID = sessionID

	// Parse the PEM-encoded public key
	block, _ := pem.Decode([]byte(peerPublicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("failed to decode PEM block containing public key")
	}

	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing public key: %v", err)
	}

	// Handle both EC and ECDH public keys
	// In both HandleKeyExchange and HandleExchangeResponse:
	var ecdhPubKey *ecdh.PublicKey
	switch p := pub.(type) {
	case *ecdh.PublicKey:
		ecdhPubKey = p
	case *ecdsa.PublicKey:
		// ECDSA keys can be used with ECDH directly if they're on the right curve
		curve := ecdh.P256()
		rawKey := elliptic.Marshal(p.Curve, p.X, p.Y)
		ecdhPubKey, err = curve.NewPublicKey(rawKey)
		if err != nil {
			return fmt.Errorf("error converting ECDSA key to ECDH format: %v", err)
		}
		fmt.Printf("Successfully converted ECDSA key to ECDH format\n")
	default:
		return fmt.Errorf("unsupported key type: %T", pub)
	}

	// Store the parsed ECDH public key
	sc.PeerPublicKey = ecdhPubKey

	// If we're the responder, send our public key back
	if !sc.IsInitiator {
		// Format our public key as PEM
		ourPublicKeyBytes, err := x509.MarshalPKIXPublicKey(sc.PrivateKey.PublicKey())
		if err != nil {
			return fmt.Errorf("error marshaling our public key: %v", err)
		}

		// Encode as PEM
		ourKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ourPublicKeyBytes,
		})

		// Create response message
		response := map[string]interface{}{
			"peer_id":    sc.PeerID,
			"session_id": sc.SessionID,
			"public_key": string(ourKeyPEM),
		}

		// Encode to JSON
		msgBytes, err := json.Marshal(response)
		if err != nil {
			return fmt.Errorf("error encoding exchange response: %v", err)
		}

		// Send response
		_, err = sc.Conn.Write([]byte(fmt.Sprintf("SECURE:EXCHANGE_RESPONSE:%s", string(msgBytes))))
		if err != nil {
			return fmt.Errorf("error sending exchange response: %v", err)
		}

		fmt.Printf("Sent key exchange response to peer %s\n", peerID)
	}

	// Derive shared secret and encryption keys
	err = sc.DeriveSharedSecret()
	if err != nil {
		return fmt.Errorf("error deriving shared secret: %v", err)
	}

	// Mark the channel as established
	sc.Established = true

	// Add to global registry
	secureChannelMutex.Lock()
	secureChannels[sc.PeerID] = sc
	secureChannelMutex.Unlock()

	fmt.Printf("Secure channel established with peer %s\n", sc.PeerID)
	return nil
}

func (sc *SecureChannel) HandleExchangeResponse(responseData map[string]interface{}) error {
	// Add more detailed logging
	fmt.Printf("Full response data: %+v\n", responseData)

	// Extract peer ID, session ID, and public key
	_, ok := responseData["peer_id"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid peer_id in exchange response: %v", responseData)
	}

	sessionID, ok := responseData["session_id"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid session_id in exchange response")
	}

	// Verify session ID matches
	if sessionID != sc.SessionID {
		return fmt.Errorf("session ID mismatch: expected %s, got %s", sc.SessionID, sessionID)
	}

	peerPublicKeyPEM, ok := responseData["public_key"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid public_key in exchange response")
	}

	// Debug log with full PEM key
	fmt.Printf("Full peer public key PEM: %s\n", peerPublicKeyPEM)

	// Parse the PEM-encoded public key
	block, _ := pem.Decode([]byte(peerPublicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("failed to decode PEM block containing public key")
	}

	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing public key: %v", err)
	}

	// Handle both EC and ECDH public keys
	// In both HandleKeyExchange and HandleExchangeResponse:
	var ecdhPubKey *ecdh.PublicKey
	switch p := pub.(type) {
	case *ecdh.PublicKey:
		ecdhPubKey = p
	case *ecdsa.PublicKey:
		// ECDSA keys can be used with ECDH directly if they're on the right curve
		curve := ecdh.P256()
		rawKey := elliptic.Marshal(p.Curve, p.X, p.Y)
		ecdhPubKey, err = curve.NewPublicKey(rawKey)
		if err != nil {
			return fmt.Errorf("error converting ECDSA key to ECDH format: %v", err)
		}
		fmt.Printf("Successfully converted ECDSA key to ECDH format\n")
	default:
		return fmt.Errorf("unsupported key type: %T", pub)
	}

	// Store the parsed ECDH public key
	sc.PeerPublicKey = ecdhPubKey

	// Derive shared secret and encryption keys
	err = sc.DeriveSharedSecret()
	if err != nil {
		return fmt.Errorf("error deriving shared secret: %v", err)
	}

	// Mark the channel as established
	sc.Established = true

	// Add to global registry
	secureChannelMutex.Lock()
	secureChannels[sc.PeerID] = sc
	secureChannelMutex.Unlock()

	fmt.Printf("Secure channel established with peer %s\n", sc.PeerID)
	return nil
}

// DeriveSharedSecret computes the shared secret for encryption
func (sc *SecureChannel) DeriveSharedSecret() error {
	// Compute shared secret using ECDH
	if sc.PeerPublicKey == nil {
		return fmt.Errorf("peer public key not set")
	}

	sharedSecret, err := sc.PrivateKey.ECDH(sc.PeerPublicKey)
	if err != nil {
		return fmt.Errorf("error computing ECDH shared secret: %v", err)
	}

	fmt.Printf("Computed shared secret for peer %s (length: %d)\n", sc.PeerID, len(sharedSecret))

	// Derive encryption and decryption keys using HKDF-like approach
	if sc.IsInitiator {
		// Initiator uses first key for sending, second for receiving
		sc.EncryptionKey = deriveKey(sharedSecret, []byte("initiator_to_responder"), 32)
		sc.DecryptionKey = deriveKey(sharedSecret, []byte("responder_to_initiator"), 32)
	} else {
		// Responder uses first key for receiving, second for sending
		sc.DecryptionKey = deriveKey(sharedSecret, []byte("initiator_to_responder"), 32)
		sc.EncryptionKey = deriveKey(sharedSecret, []byte("responder_to_initiator"), 32)
	}

	// Clear private key for forward secrecy
	sc.PrivateKey = nil

	return nil
}
func (sc *SecureChannel) EncryptMessage(plaintext []byte) (string, error) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if !sc.Established || sc.EncryptionKey == nil {
		return "", fmt.Errorf("secure channel not established")
	}
	// print length ofsc.encryptionkey
	fmt.Printf("Encrypt: encryption key length: %d\n", len(sc.EncryptionKey))
	// Create AES-GCM cipher
	block, err := aes.NewCipher(sc.EncryptionKey)
	if err != nil {
		return "", fmt.Errorf("error creating cipher: %v", err)
	}

	// Generate a nonce using the counter
	nonce := make([]byte, 12)
	// Use session ID as prefix (first 8 bytes)
	copy(nonce, []byte(sc.SessionID[:8]))
	// Use counter for the last 4 bytes
	nonce[8] = byte(sc.SendCounter >> 24)
	nonce[9] = byte(sc.SendCounter >> 16)
	nonce[10] = byte(sc.SendCounter >> 8)
	nonce[11] = byte(sc.SendCounter)

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creating GCM: %v", err)
	}

	// Create additional data (AAD) for authentication
	aad := []byte(fmt.Sprintf("%s:%s:%d", sc.PeerID, sc.SessionID, sc.SendCounter))

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// Increment the counter
	sc.SendCounter++

	// Format: base64(nonce) + ":" + base64(ciphertext)
	encryptedMessage := base64.StdEncoding.EncodeToString(nonce) + ":" +
		base64.StdEncoding.EncodeToString(ciphertext)

	return encryptedMessage, nil
}

// DecryptMessage decrypts a message using AES-GCM
func (sc *SecureChannel) DecryptMessage(encryptedMessage string) ([]byte, error) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if !sc.Established || sc.DecryptionKey == nil {
		return nil, fmt.Errorf("secure channel not established")
	}

	// Parse the encrypted message
	parts := strings.Split(encryptedMessage, ":")
	fmt.Printf("Decrypt: got %d parts, expecting 2\n", len(parts))

	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid encrypted message format")
	}

	nonce, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("error decoding nonce: %v", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error decoding ciphertext: %v", err)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(sc.DecryptionKey)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %v", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %v", err)
	}

	// Create additional data (AAD) for authentication
	aad := []byte(fmt.Sprintf("%s:%s:%d", sc.PeerID, sc.SessionID, sc.ReceiveCounter))

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("error decrypting message: %v", err)
	}

	// Increment the counter
	sc.ReceiveCounter++

	return plaintext, nil
}

func (sc *SecureChannel) SendEncrypted(messageType, payload string) error {
	if !sc.Established {
		return fmt.Errorf("cannot send encrypted message - channel not established")
	}

	// Construct the plaintext message
	plaintext := []byte(fmt.Sprintf("%s:%s", messageType, payload))

	// Encrypt the message
	encrypted, err := sc.EncryptMessage(plaintext)
	if err != nil {
		return fmt.Errorf("error encrypting message: %v", err)
	}

	// Additional logging
	fmt.Printf("Sending encrypted message: Type=%s, Payload=%s, Encrypted=%s\n",
		messageType, payload, encrypted)

	// Send the encrypted message
	_, err = sc.Conn.Write([]byte(fmt.Sprintf("SECURE:DATA:%s", encrypted)))
	if err != nil {
		return fmt.Errorf("error sending encrypted message: %v", err)
	}

	return nil
}

// HandleEncryptedData processes an incoming encrypted message
func (sc *SecureChannel) HandleEncryptedData(encryptedData string) (map[string]string, error) {
	// Decrypt the message
	plaintext, err := sc.DecryptMessage(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("error decrypting message: %v", err)
	}

	// Parse the plaintext message
	message := string(plaintext)
	parts := strings.SplitN(message, ":", 2)

	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid decrypted message format")
	}

	messageType := parts[0]
	payload := parts[1]

	result := map[string]string{
		"type":    messageType,
		"payload": payload,
	}

	return result, nil
}

// Close closes the secure channel and cleans up resources
func (sc *SecureChannel) Close() {
	// Remove from global registry
	secureChannelMutex.Lock()
	delete(secureChannels, sc.PeerID)
	secureChannelMutex.Unlock()

	// Clear sensitive data
	sc.EncryptionKey = nil
	sc.DecryptionKey = nil
	sc.PrivateKey = nil
	sc.PeerPublicKey = nil

	sc.Established = false
	fmt.Printf("Secure channel with peer %s closed\n", sc.PeerID)
}
func GetSecureChannel(peerID string) *SecureChannel {
	secureChannelMutex.RLock()
	defer secureChannelMutex.RUnlock()
	return secureChannels[peerID]
}

// HandleSecureMessage processes secure protocol messages
func HandleSecureMessage(conn net.Conn, addr string, message string) (map[string]interface{}, error) {
	parts := strings.SplitN(message, ":", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid secure message format: %s", message)
	}

	secureCommand := parts[1]
	payload := parts[2]

	switch secureCommand {
	case "EXCHANGE":
		// Handle key exchange request
		var exchangeData map[string]interface{}
		err := json.Unmarshal([]byte(payload), &exchangeData)
		if err != nil {
			return nil, fmt.Errorf("error parsing exchange data: %v", err)
		}

		peerID, ok := exchangeData["peer_id"].(string)
		if !ok {
			return nil, fmt.Errorf("missing peer_id in exchange data")
		}

		// Check if peer is authenticated
		contactManager, err := GetContactManager()
		if err != nil {
			return nil, fmt.Errorf("error getting contact manager: %v", err)
		}

		// For security, only allow authenticated peers to establish secure channels
		hostPort := strings.Split(addr, ":")
		if len(hostPort) != 2 {
			return nil, fmt.Errorf("invalid address format: %s", addr)
		}
		standardAddr := fmt.Sprintf("%s:12345", hostPort[0])

		_, isTrusted := contactManager.GetContactByAddress(standardAddr)
		if !isTrusted {
			return nil, fmt.Errorf("peer not authenticated: %s", peerID)
		}

		// Create a new secure channel as responder
		channel, err := NewSecureChannel(peerID, conn, false)
		if err != nil {
			return nil, fmt.Errorf("error creating secure channel: %v", err)
		}

		// Handle the exchange
		err = channel.HandleKeyExchange(exchangeData)
		if err != nil {
			return nil, fmt.Errorf("error handling key exchange: %v", err)
		}

		return map[string]interface{}{
			"status":  "secure_channel_established",
			"peer_id": peerID,
		}, nil

	case "EXCHANGE_RESPONSE":
		// Handle key exchange response
		var responseData map[string]interface{}
		err := json.Unmarshal([]byte(payload), &responseData)
		if err != nil {
			return nil, fmt.Errorf("error parsing exchange response: %v", err)
		}

		peerID, ok := responseData["peer_id"].(string)
		if !ok {
			return nil, fmt.Errorf("missing peer_id in exchange response")
		}

		// Find the channel
		channel := GetSecureChannel(peerID)
		if channel == nil {
			return nil, fmt.Errorf("no pending secure channel for peer %s", peerID)
		}

		// Handle the exchange response
		err = channel.HandleExchangeResponse(responseData)
		if err != nil {
			return nil, fmt.Errorf("error handling exchange response: %v", err)
		}

		return map[string]interface{}{
			"status":  "secure_channel_established",
			"peer_id": peerID,
		}, nil

	case "DATA":
		// Handle encrypted data
		// Find the channel based on the socket address
		hostPort := strings.Split(addr, ":")
		if len(hostPort) != 2 {
			return nil, fmt.Errorf("invalid address format: %s", addr)
		}
		standardAddr := fmt.Sprintf("%s:12345", hostPort[0])

		contactManager, err := GetContactManager()
		if err != nil {
			return nil, fmt.Errorf("error getting contact manager: %v", err)
		}

		contact, found := contactManager.GetContactByAddress(standardAddr)
		if !found {
			return nil, fmt.Errorf("no authenticated contact for %s", standardAddr)
		}

		peerID := contact.PeerID
		channel := GetSecureChannel(peerID)

		if channel == nil {
			return nil, fmt.Errorf("no secure channel established for peer %s", peerID)
		}

		// Decrypt and handle the data
		result, err := channel.HandleEncryptedData(payload)
		if err != nil {
			return nil, fmt.Errorf("error handling encrypted data: %v", err)
		}

		return map[string]interface{}{
			"status":  "message_received",
			"peer_id": peerID,
			"type":    result["type"],
			"payload": result["payload"],
		}, nil

	default:
		return nil, fmt.Errorf("unknown secure command: %s", secureCommand)
	}
}

func EstablishSecureChannel(peerID, peerAddr string) (map[string]interface{}, error) {
	// Validate inputs first
	if peerID == "" {
		return nil, fmt.Errorf("peer ID cannot be empty")
	}

	// Parse address
	hostPort := strings.Split(peerAddr, ":")
	if len(hostPort) != 2 {
		return nil, fmt.Errorf("invalid address format: %s", peerAddr)
	}

	host := hostPort[0]
	port := hostPort[1]

	fmt.Printf("Establishing secure channel with peer %s at %s:%s...\n", peerID, host, port)

	// Create a new socket connection
	conn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("error connecting to %s: %v", peerAddr, err)
	}

	// Create a secure channel
	channel, err := NewSecureChannel(peerID, conn, true)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("error creating secure channel: %v", err)
	}

	// Initiate key exchange
	err = channel.InitiateKeyExchange()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("error initiating key exchange: %v", err)
	}

	fmt.Printf("Key exchange initiated with peer %s\n", peerID)

	// Add channel to global registry while we wait for response
	secureChannelMutex.Lock()
	secureChannels[peerID] = channel
	secureChannelMutex.Unlock()

	// Create buffered channels to avoid goroutine leaks
	doneChan := make(chan bool, 1)
	errChan := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- fmt.Errorf("panic during secure channel establishment: %v", r)
			}
		}()

		buffer := make([]byte, 8192)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				errChan <- fmt.Errorf("connection error from peer %s: %v", peerAddr, err)
				return
			}

			message := string(buffer[:n])
			fmt.Printf("Received full message from peer: %s\n", message)

			// More robust parsing
			if strings.Contains(message, "SECURE:EXCHANGE_RESPONSE:") {
				parts := strings.SplitN(message, ":", 3)
				if len(parts) >= 3 {
					var responseData map[string]interface{}
					err = json.Unmarshal([]byte(parts[2]), &responseData)
					if err != nil {
						errChan <- fmt.Errorf("error parsing exchange response: %v", err)
						return
					}

					// Verify peer ID matches
					responsePeerID, ok := responseData["peer_id"].(string)
					if !ok || responsePeerID != peerID {
						errChan <- fmt.Errorf("peer ID mismatch: expected %s, got %v", peerID, responsePeerID)
						return
					}

					// Print full response data for debugging
					fmt.Printf("Parsed response data: %+v\n", responseData)

					err = channel.HandleExchangeResponse(responseData)
					if err != nil {
						errChan <- fmt.Errorf("error handling exchange response: %v", err)
						return
					}

					// Signal that the exchange is complete
					doneChan <- true
					return
				}
			}
		}
	}()

	// Wait for the channel to be established (with timeout)
	const maxWaitTime = 10 * time.Second

	select {
	case <-doneChan:
		if !channel.Established {
			return map[string]interface{}{
				"status":  "failed",
				"message": "Channel not fully established",
			}, fmt.Errorf("channel not fully established")
		}
		fmt.Printf("Secure channel established with peer %s\n", peerID)
		return map[string]interface{}{
			"status":  "established",
			"channel": channel,
			"conn":    conn, // Return the connection so it's not closed
		}, nil
	case err := <-errChan:
		conn.Close()
		fmt.Printf("Error establishing secure channel: %v\n", err)
		return map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		}, err
	case <-time.After(maxWaitTime):
		conn.Close()
		fmt.Printf("Secure channel not established after waiting %v - current status: %v\n",
			maxWaitTime, channel.Established)

		return map[string]interface{}{
			"status":  "timeout",
			"message": "Secure channel establishment timed out",
		}, fmt.Errorf("secure channel establishment timed out")
	}
}

// Helper function for min(a, b)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Global instance of the contact manager
var globalContactManager *ContactManager
var contactManagerMutex sync.RWMutex

// SetContactManager sets the global contact manager
func SetContactManager(cm *ContactManager) {
	contactManagerMutex.Lock()
	defer contactManagerMutex.Unlock()
	globalContactManager = cm
}

// GetContactManager gets the global contact manager
func GetContactManager() (*ContactManager, error) {
	contactManagerMutex.RLock()
	defer contactManagerMutex.RUnlock()

	if globalContactManager == nil {
		return nil, fmt.Errorf("contact manager not initialized")
	}

	return globalContactManager, nil
}
