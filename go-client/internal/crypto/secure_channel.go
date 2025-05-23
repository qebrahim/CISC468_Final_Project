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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

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
type SecureFileTransfer struct {
	Filename string
	Path     string
	Size     int64
	Hash     string
	Key      []byte
	Received int64
	File     *os.File
}

// Global registry of secure channels
var (
	secureChannels     = make(map[string]*SecureChannel)
	secureChannelMutex sync.RWMutex
)
var secureFileTransfers = make(map[string]*SecureFileTransfer)
var fileTransferMutex sync.Mutex

var addrToPeerID = make(map[string]string)
var addrToPeerIDMutex sync.RWMutex

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

	// Print debug information
	fmt.Printf("Go Encrypt Debug: encryption key length: %d\n", len(sc.EncryptionKey))
	fmt.Printf("Go Encrypt Debug: encryption key (hex): %x\n", sc.EncryptionKey)
	fmt.Printf("Go Encrypt Debug: plaintext length: %d\n", len(plaintext))
	fmt.Printf("Go Encrypt Debug: plaintext: %s\n", string(plaintext))

	// Create AES-GCM cipher
	block, err := aes.NewCipher(sc.EncryptionKey)
	if err != nil {
		fmt.Printf("Go Encrypt Error: creating cipher: %v\n", err)
		return "", fmt.Errorf("error creating cipher: %v", err)
	}

	// Generate a nonce using the counter
	nonce := make([]byte, 12)
	// Use session ID as prefix (first 8 bytes)
	sessionIDBytes := []byte(sc.SessionID[:8])
	fmt.Printf("Go Encrypt Debug: session ID for nonce: %s\n", sc.SessionID[:8])
	fmt.Printf("Go Encrypt Debug: session ID bytes for nonce (hex): %x\n", sessionIDBytes)

	copy(nonce, sessionIDBytes)

	// Use counter for the last 4 bytes
	counterBytes := make([]byte, 4)
	counterBytes[0] = byte(sc.SendCounter >> 24)
	counterBytes[1] = byte(sc.SendCounter >> 16)
	counterBytes[2] = byte(sc.SendCounter >> 8)
	counterBytes[3] = byte(sc.SendCounter)

	fmt.Printf("Go Encrypt Debug: counter for nonce: %d\n", sc.SendCounter)
	fmt.Printf("Go Encrypt Debug: counter bytes for nonce (hex): %x\n", counterBytes)

	copy(nonce[8:], counterBytes)
	fmt.Printf("Go Encrypt Debug: complete nonce (hex): %x\n", nonce)

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Go Encrypt Error: creating GCM: %v\n", err)
		return "", fmt.Errorf("error creating GCM: %v", err)
	}

	// Create additional data (AAD) for authentication
	aadStr := fmt.Sprintf("%s:%s:%d", sc.PeerID, sc.SessionID, sc.SendCounter)
	aad := []byte(aadStr)

	fmt.Printf("Go Encrypt Debug: AAD string: %s\n", aadStr)
	fmt.Printf("Go Encrypt Debug: AAD bytes (hex): %x\n", aad)

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	fmt.Printf("Go Encrypt Debug: full ciphertext+tag length: %d\n", len(ciphertext))

	// GCM tag is always at the end, standard length is 16 bytes
	tagStart := len(ciphertext) - 16
	tag := ciphertext[tagStart:]
	actualCiphertext := ciphertext[:tagStart]

	fmt.Printf("Go Encrypt Debug: actual ciphertext length: %d\n", len(actualCiphertext))
	fmt.Printf("Go Encrypt Debug: tag length: %d\n", len(tag))
	fmt.Printf("Go Encrypt Debug: tag (hex): %x\n", tag)

	// Increment the counter
	sc.SendCounter++

	// Format: base64(nonce) + ":" + base64(ciphertext)
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)
	encryptedMessage := nonceB64 + ":" + ciphertextB64

	fmt.Printf("Go Encrypt Debug: nonce base64: %s\n", nonceB64)
	fmt.Printf("Go Encrypt Debug: ciphertext+tag base64: %s\n", ciphertextB64)
	fmt.Printf("Go Encrypt Debug: final encrypted message: %s\n", encryptedMessage)

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

	fmt.Printf("Handling encrypted message: Type=%s, Payload=%s\n", messageType, payload)

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

// Then modify the HandleSecureMessage function to properly store and look up peer IDs by address:

func HandleSecureMessage(conn net.Conn, addr string, message string) (map[string]interface{}, error) {
	// Debug the inputs to see what's coming in
	fmt.Printf("DEBUG: HandleSecureMessage called with addr='%s', message='%s'\n", addr, message)

	parts := strings.SplitN(message, ":", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid secure message format: %s", message)
	}

	fmt.Printf("DEBUG: Message parts: %v\n", parts)

	secureCommand := parts[1]
	payload := parts[2]

	// Extract host and port from addr properly
	var host, port string
	fmt.Printf("DEBUG: port before processing: %s\n", port)
	if addr != "" && strings.Contains(addr, ":") {
		hostPort := strings.Split(addr, ":")
		if len(hostPort) >= 2 {
			host = hostPort[0]
			//port = hostPort[1]
		} else {
			return nil, fmt.Errorf("invalid address format: %s", addr)
		}
	} else {
		if conn != nil && conn.RemoteAddr() != nil {
			remoteAddr := conn.RemoteAddr().String()
			hostPort := strings.Split(remoteAddr, ":")
			if len(hostPort) >= 2 {
				host = hostPort[0]
				//port = hostPort[1]
			} else {
				host = addr
				port = "12345" // Default port
			}
		} else {
			host = addr
			port = "12345" // Default port
		}
	}

	// Use the standard port format for address lookups
	standardAddr := fmt.Sprintf("%s:12345", host)

	// Look up the peer using the address
	contactManager, err := GetContactManager()
	if err != nil {
		fmt.Printf("DEBUG: Error getting contact manager: %v\n", err)
	} else {
		fmt.Printf("Looking for contact with address: %s\n", standardAddr)
		fmt.Printf("Current contacts: %+v\n", contactManager.Contacts)

		// Get peer ID from contact manager by address
		contact, found := contactManager.GetContactByAddress(standardAddr)
		if found {
			// Store mapping between address and peer ID
			addrToPeerIDMutex.Lock()
			addrToPeerID[addr] = contact.PeerID
			addrToPeerIDMutex.Unlock()

			fmt.Printf("DEBUG: Mapped address %s to peer ID %s\n", addr, contact.PeerID)
		}
	}

	// Try to get peer ID from address mapping
	var peerID string
	addrToPeerIDMutex.RLock()
	mappedPeerID, exists := addrToPeerID[addr]
	addrToPeerIDMutex.RUnlock()

	if exists {
		peerID = mappedPeerID
		fmt.Printf("DEBUG: Using mapped peer ID %s for address %s\n", peerID, addr)
	} else if secureCommand == "EXCHANGE" || secureCommand == "EXCHANGE_RESPONSE" {
		// For exchange messages, extract peer ID from payload
		var exchangeData map[string]interface{}
		if err := json.Unmarshal([]byte(payload), &exchangeData); err == nil {
			if extractedPeerID, ok := exchangeData["peer_id"].(string); ok {
				peerID = extractedPeerID
				// Store the mapping
				addrToPeerIDMutex.Lock()
				addrToPeerID[addr] = peerID
				addrToPeerIDMutex.Unlock()
				fmt.Printf("DEBUG: Extracted and mapped peer ID %s from payload for address %s\n", peerID, addr)
			}
		}
	}

	// Now handle the message based on command
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

		// Store mapping between address and peer ID
		addrToPeerIDMutex.Lock()
		addrToPeerID[addr] = peerID
		addrToPeerIDMutex.Unlock()
		fmt.Printf("Mapped connection pointer %v to peer ID %s\n", addr, peerID)

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

		// Store mapping between address and peer ID
		addrToPeerIDMutex.Lock()
		addrToPeerID[addr] = peerID
		addrToPeerIDMutex.Unlock()

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
		// Use either the peerID we found earlier or try to get it from the stored mappings
		channelPeerID := peerID

		if channelPeerID == "" {
			// Look up in all the places we might have stored the mapping
			addrToPeerIDMutex.RLock()
			if mappedID, exists := addrToPeerID[addr]; exists {
				channelPeerID = mappedID
				fmt.Printf("DEBUG: Found peer ID %s from address mapping for %s\n", channelPeerID, addr)
			}
			addrToPeerIDMutex.RUnlock()

			if channelPeerID == "" && conn != nil {
				connID := fmt.Sprintf("%p", conn)
				fmt.Printf("DEBUG: Looking for peer ID by connection %s\n", connID)
				secureChannelMutex.RLock()
				for id, ch := range secureChannels {
					if ch.Conn == conn {
						channelPeerID = id
						fmt.Printf("DEBUG: Found peer ID %s by matching connection\n", channelPeerID)
						break
					}
				}
				secureChannelMutex.RUnlock()
			}

			if channelPeerID == "" {
				return nil, fmt.Errorf("no secure channel established for peer address %s", addr)
			}
		}

		channel := GetSecureChannel(channelPeerID)

		if channel == nil {
			// Try looking up by connection
			secureChannelMutex.RLock()
			for id, ch := range secureChannels {
				if ch.Conn == conn {
					channel = ch
					channelPeerID = id
					fmt.Printf("DEBUG: Found channel for peer %s by matching connection\n", channelPeerID)
					break
				}
			}
			secureChannelMutex.RUnlock()

			if channel == nil {
				return nil, fmt.Errorf("no secure channel established for peer %s", channelPeerID)
			}
		}

		// Decrypt and handle the data
		result, err := channel.HandleEncryptedData(payload)
		if err != nil {
			return nil, fmt.Errorf("error handling encrypted data: %v", err)
		}

		return map[string]interface{}{
			"status":  "message_received",
			"peer_id": channelPeerID,
			"type":    result["type"],
			"payload": result["payload"],
		}, nil

	default:
		return nil, fmt.Errorf("unknown secure command: %s", secureCommand)
	}
}
func handleSecureFileHeader(peerID, payload string) {
	fmt.Printf("Received file header from %s\n", peerID)

	// Parse the header JSON
	var header map[string]interface{}
	err := json.Unmarshal([]byte(payload), &header)
	if err != nil {
		fmt.Printf("Error parsing file header: %v\n", err)
		return
	}

	// Extract file information
	filename, ok := header["filename"].(string)
	if !ok {
		fmt.Printf("Missing filename in header\n")
		return
	}

	size, ok := header["size"].(float64)
	if !ok {
		fmt.Printf("Missing file size in header\n")
		return
	}

	// Get hash if available
	var hash string
	if hashVal, ok := header["hash"].(string); ok {
		hash = hashVal
	}

	// Get encryption key if available
	var key []byte
	if keyB64, ok := header["key"].(string); ok {
		key, err = base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			fmt.Printf("Error decoding encryption key: %v\n", err)
		} else {
			fmt.Printf("Got encryption key for file (length: %d)\n", len(key))
		}
	}

	// Create directory for downloads
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Error getting user home directory: %v\n", err)
		return
	}

	downloadDir := filepath.Join(homeDir, ".p2p-share", "shared")
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		fmt.Printf("Error creating download directory: %v\n", err)
		return
	}

	// Create file
	savePath := filepath.Join(downloadDir, filename)
	file, err := os.Create(savePath)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}

	// Store transfer state
	fileTransferMutex.Lock()
	secureFileTransfers[peerID] = &SecureFileTransfer{
		Filename: filename,
		Path:     savePath,
		Size:     int64(size),
		Hash:     hash,
		Key:      key,
		Received: 0,
		File:     file,
	}
	fileTransferMutex.Unlock()

	fmt.Printf("\nReceiving file: %s (%d bytes)\n", filename, int64(size))
}

func handleSecureFileChunk(peerID, payload string) {
	fileTransferMutex.Lock()
	transfer, exists := secureFileTransfers[peerID]
	fileTransferMutex.Unlock()

	if !exists {
		fmt.Printf("No active file transfer for peer %s\n", peerID)
		return
	}

	// Decode the base64 chunk
	encryptedChunk, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		fmt.Printf("Error decoding file chunk: %v\n", err)
		return
	}

	// Decrypt if we have a key
	var chunk []byte
	if transfer.Key != nil {
		// Decrypt the chunk
		block, err := aes.NewCipher(transfer.Key)
		if err != nil {
			fmt.Printf("Error creating cipher: %v\n", err)
			return
		}

		// First 12 bytes should be IV, next 16 are tag
		if len(encryptedChunk) < 28 {
			fmt.Printf("Encrypted chunk too short\n")
			return
		}

		iv := encryptedChunk[:12]
		tag := encryptedChunk[12:28]
		ciphertext := encryptedChunk[28:]

		fmt.Printf("Decrypting chunk (length: %d)\n", len(ciphertext))
		fmt.Printf("IV (hex): %x\n", iv)
		fmt.Printf("Tag (hex): %x\n", tag)
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			fmt.Printf("Error creating GCM: %v\n", err)
			return
		}

		// Try decryption
		chunk, err = gcm.Open(nil, iv, encryptedChunk[12:], nil)
		if err != nil {
			fmt.Printf("Error decrypting chunk: %v\n", err)
			// Fall back to using the raw chunk
			chunk = encryptedChunk
		}
	} else {
		// No encryption, use the raw chunk
		chunk = encryptedChunk
	}

	// Write to file
	_, err = transfer.File.Write(chunk)
	if err != nil {
		fmt.Printf("Error writing file chunk: %v\n", err)
		return
	}

	// Update received count
	transfer.Received += int64(len(chunk))

	// Display progress
	if transfer.Size > 0 {
		percent := float64(transfer.Received) / float64(transfer.Size) * 100
		fmt.Printf("\rReceiving: %.1f%%", percent)
	}
}

func handleSecureFileEnd(peerID, payload string) {
	fmt.Printf("\nFile transfer from %s completed\n", peerID)

	fileTransferMutex.Lock()
	transfer, exists := secureFileTransfers[peerID]
	fileTransferMutex.Unlock()

	if !exists {
		fmt.Printf("No active file transfer for peer %s\n", peerID)
		return
	}

	// Close the file
	if transfer.File != nil {
		transfer.File.Close()
	}

	fmt.Printf("Received file: %s (%d bytes)\n", transfer.Filename, transfer.Received)

	// Verify hash if available
	if transfer.Hash != "" {
		fmt.Printf("Hash verification not implemented yet\n")
		// You could add hash verification here
	}

	// Cleanup
	fileTransferMutex.Lock()
	delete(secureFileTransfers, peerID)
	fileTransferMutex.Unlock()

	fmt.Printf("\nFile download complete: %s\n", transfer.Path)
}

func handleSecureFileList(peerID, payload string) {
	fmt.Printf("Received file list from peer %s\n", peerID)

	if payload == "" {
		fmt.Printf("No files available from peer\n")
		return
	}

	// Determine the format of the file list
	var files []string

	if strings.Contains(payload, ";") {
		// New format with file entries separated by semicolons
		files = strings.Split(payload, ";")
	} else if strings.Contains(payload, ",") {
		// Check if it's comma-separated files or individual file with metadata
		if strings.Count(payload, ",") == 2 {
			// Single file entry with hash and size
			files = []string{payload}
		} else {
			// Old format with comma-separated filenames
			files = strings.Split(payload, ",")
		}
	} else if payload != "" {
		// Single file with no metadata
		files = []string{payload}
	}

	if len(files) == 0 {
		fmt.Printf("No files available from peer\n")
		return
	}

	fmt.Printf("\nFiles available from peer %s:\n", peerID)

	for i, file := range files {
		if file == "" {
			continue
		}

		// Check if file has metadata
		if strings.Count(file, ",") == 2 {
			// Parse file,hash,size triplet
			parts := strings.Split(file, ",")
			filename := parts[0]
			hash := parts[1]
			sizeStr := parts[2]

			// Format size display
			sizeDisplay := ""
			if sizeStr != "" {
				size, err := strconv.ParseInt(sizeStr, 10, 64)
				if err == nil {
					if size < 1024 {
						sizeDisplay = fmt.Sprintf(" (%d bytes)", size)
					} else if size < 1024*1024 {
						sizeDisplay = fmt.Sprintf(" (%.1f KB)", float64(size)/1024)
					} else {
						sizeDisplay = fmt.Sprintf(" (%.1f MB)", float64(size)/(1024*1024))
					}
				}
			}

			verifiedStr := ""
			if hash != "" {
				verifiedStr = " [verifiable]"
			}

			fmt.Printf("%d. %s%s%s\n", i+1, filename, sizeDisplay, verifiedStr)
		} else {
			// Simple filename without metadata
			fmt.Printf("%d. %s\n", i+1, file)
		}
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
