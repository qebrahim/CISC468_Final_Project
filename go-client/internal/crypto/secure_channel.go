package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

// SecureChannel implements encrypted communication using ECDHE for forward secrecy
type SecureChannel struct {
	PeerID         string
	Conn           net.Conn
	IsInitiator    bool
	Established    bool
	SessionID      string
	PrivateKey     *ecdh.PrivateKey
	PublicKey      *ecdh.PublicKey
	PeerPublicKey  *ecdh.PublicKey
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

// NewSecureChannel creates a new secure channel for a peer
func NewSecureChannel(peerID string, conn net.Conn, isInitiator bool) (*SecureChannel, error) {
	// Generate ephemeral ECDH key pair
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("error generating ephemeral key: %v", err)
	}

	publicKey := privateKey.PublicKey()

	sc := &SecureChannel{
		PeerID:      peerID,
		Conn:        conn,
		IsInitiator: isInitiator,
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
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

	// Serialize public key to bytes
	publicKeyBytes := sc.PublicKey.Bytes()
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

	// Create key exchange message
	keyExchangeMsg := map[string]interface{}{
		"peer_id":    sc.PeerID,
		"session_id": sc.SessionID,
		"public_key": publicKeyB64,
	}

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

// HandleKeyExchange processes a key exchange message from a peer
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

	peerPublicKeyB64, ok := exchangeData["public_key"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid public_key in key exchange")
	}

	// Store session ID
	sc.SessionID = sessionID

	// Decode and import peer's public key
	peerPublicKeyBytes, err := base64.StdEncoding.DecodeString(peerPublicKeyB64)
	if err != nil {
		return fmt.Errorf("error decoding public key: %v", err)
	}

	peerPublicKey, err := ecdh.P256().NewPublicKey(peerPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("error importing public key: %v", err)
	}
	sc.PeerPublicKey = peerPublicKey

	// If we're the responder, send our public key back
	if !sc.IsInitiator {
		publicKeyBytes := sc.PublicKey.Bytes()
		publicKeyB64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

		// Create response message
		response := map[string]interface{}{
			"peer_id":    sc.PeerID,
			"session_id": sc.SessionID,
			"public_key": publicKeyB64,
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

// HandleExchangeResponse processes a key exchange response from a peer
func (sc *SecureChannel) HandleExchangeResponse(responseData map[string]interface{}) error {
	// Extract peer ID, session ID, and public key
	peerID, ok := responseData["peer_id"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid peer_id in exchange response: %s", peerID)
	}

	sessionID, ok := responseData["session_id"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid session_id in exchange response")
	}

	// Verify session ID matches
	if sessionID != sc.SessionID {
		return fmt.Errorf("session ID mismatch: expected %s, got %s", sc.SessionID, sessionID)
	}

	peerPublicKeyB64, ok := responseData["public_key"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid public_key in exchange response")
	}

	// Decode and import peer's public key
	peerPublicKeyBytes, err := base64.StdEncoding.DecodeString(peerPublicKeyB64)
	if err != nil {
		return fmt.Errorf("error decoding public key: %v", err)
	}

	peerPublicKey, err := ecdh.P256().NewPublicKey(peerPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("error importing public key: %v", err)
	}
	sc.PeerPublicKey = peerPublicKey

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

// DeriveSharedSecret computes shared secret using ECDHE
func (sc *SecureChannel) DeriveSharedSecret() error {
	// Compute shared secret
	sharedSecret, err := sc.PrivateKey.ECDH(sc.PeerPublicKey)
	if err != nil {
		return fmt.Errorf("error computing shared secret: %v", err)
	}

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
	// Note: Go doesn't have a direct way to securely clear memory
	// In a production system, you would use a more secure approach
	sc.PrivateKey = nil

	return nil
}

// deriveKey derives a key from shared secret using a simple KDF
func deriveKey(secret, info []byte, length int) []byte {
	h := sha256.New()
	h.Write(secret)
	h.Write(info)
	return h.Sum(nil)[:length]
}

// EncryptMessage encrypts a message using AES-GCM
func (sc *SecureChannel) EncryptMessage(plaintext []byte) (string, error) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if !sc.Established || sc.EncryptionKey == nil {
		return "", fmt.Errorf("secure channel not established")
	}

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

// SendEncrypted sends an encrypted message over the secure channel
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

// GetSecureChannel gets an existing secure channel for a peer
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

// EstablishSecureChannel establishes a secure channel with a peer
func EstablishSecureChannel(peerID, peerAddr string) (map[string]interface{}, error) {
	// Parse address
	hostPort := strings.Split(peerAddr, ":")
	if len(hostPort) != 2 {
		return nil, fmt.Errorf("invalid address format: %s", peerAddr)
	}

	host := hostPort[0]
	port := hostPort[1]

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

	// The rest of the exchange will be handled by the protocol handler
	// when the peer responds

	return map[string]interface{}{
		"status":  "initiated",
		"channel": channel,
	}, nil
}

// EncryptFile encrypts a file using AES-GCM
func EncryptFile(inputFile, outputFile string, key []byte) error {
	// Open input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %v", err)
	}
	defer inFile.Close()

	// Create output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outFile.Close()

	// Generate a random IV (12 bytes for GCM)
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("error generating IV: %v", err)
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %v", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating GCM: %v", err)
	}

	// Write IV to the output file
	if _, err := outFile.Write(iv); err != nil {
		return fmt.Errorf("error writing IV: %v", err)
	}

	// Read the input file
	data, err := io.ReadAll(inFile)
	if err != nil {
		return fmt.Errorf("error reading input file: %v", err)
	}

	// Encrypt the data
	encrypted := gcm.Seal(nil, iv, data, nil)

	// Write the encrypted data to the output file
	if _, err := outFile.Write(encrypted); err != nil {
		return fmt.Errorf("error writing encrypted data: %v", err)
	}

	return nil
}

// DecryptFile decrypts a file using AES-GCM
func DecryptFile(inputFile, outputFile string, key []byte) error {
	// Open input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %v", err)
	}
	defer inFile.Close()

	// Create output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outFile.Close()

	// Read the IV from the input file
	iv := make([]byte, 12)
	if _, err := io.ReadFull(inFile, iv); err != nil {
		return fmt.Errorf("error reading IV: %v", err)
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %v", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating GCM: %v", err)
	}

	// Read the encrypted data
	data, err := io.ReadAll(inFile)
	if err != nil {
		return fmt.Errorf("error reading encrypted data: %v", err)
	}

	// Decrypt the data
	decrypted, err := gcm.Open(nil, iv, data, nil)
	if err != nil {
		return fmt.Errorf("error decrypting data: %v", err)
	}

	// Write the decrypted data to the output file
	if _, err := outFile.Write(decrypted); err != nil {
		return fmt.Errorf("error writing decrypted data: %v", err)
	}

	return nil
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
