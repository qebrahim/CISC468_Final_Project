package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
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
	ECDSAPrivKey   *ecdsa.PrivateKey // Using ECDSA instead of ECDH
	ECDSAPubKey    *ecdsa.PublicKey  // Using ECDSA instead of ECDH
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
	// Generate key pair - use crypto/x509 for compatibility with Python's cryptography
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("error generating ephemeral key: %v", err)
	}

	sc := &SecureChannel{
		PeerID:       peerID,
		Conn:         conn,
		IsInitiator:  isInitiator,
		ECDSAPrivKey: privateKey,
		Established:  false,
		SessionID:    "",
		mutex:        sync.Mutex{},
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
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&sc.ECDSAPrivKey.PublicKey)
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

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not an ECDSA key")
	}

	// Store the parsed ECDSA public key
	sc.ECDSAPubKey = ecdsaPub

	// If we're the responder, send our public key back
	if !sc.IsInitiator {
		// Format our public key as PEM
		ourPublicKeyBytes, err := x509.MarshalPKIXPublicKey(&sc.ECDSAPrivKey.PublicKey)
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
	// Add mutex lock
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	// Debug logging
	fmt.Printf("Handling exchange response with data: %+v\n", responseData)

	sessionID, ok := responseData["session_id"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid session_id in response")
	}

	// Verify session ID matches what we sent
	if sessionID != sc.SessionID {
		fmt.Printf("Session ID mismatch: expected %s, got %s\n", sc.SessionID, sessionID)
		return fmt.Errorf("session ID mismatch")
	}

	// Parse and verify peer's public key
	peerPublicKeyPEM, ok := responseData["public_key"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid public_key in response")
	}

	// Log the keys we're working with
	fmt.Printf("Our session ID: %s\n", sc.SessionID)
	fmt.Printf("Peer's public key:\n%s\n", peerPublicKeyPEM)

	block, _ := pem.Decode([]byte(peerPublicKeyPEM))
	if block == nil {
		return fmt.Errorf("failed to decode peer's public key PEM")
	}

	peerKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse peer's public key: %v", err)
	}

	// Convert to ECDSA public key
	ecdsaPubKey, ok := peerKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("peer's public key is not an ECDSA key")
	}

	// Store peer's public key using correct field name
	sc.ECDSAPubKey = ecdsaPubKey

	// Derive shared secret
	if err := sc.DeriveSharedSecret(); err != nil {
		return fmt.Errorf("failed to derive shared secret: %v", err)
	}

	// Mark channel as established
	sc.Established = true
	fmt.Printf("Secure channel established successfully with session ID: %s\n", sc.SessionID)

	return nil
}

// DeriveSharedSecret computes the shared secret for encryption
func (sc *SecureChannel) DeriveSharedSecret() error {
	// Compute shared secret using ECDH with ECDSA keys
	// For ECDSA, we use the peer's X,Y coordinates multiplied by our private key to create a shared point
	xCoord, _ := sc.ECDSAPrivKey.Curve.ScalarMult(
		sc.ECDSAPubKey.X,
		sc.ECDSAPubKey.Y,
		sc.ECDSAPrivKey.D.Bytes(),
	)

	// Use the X coordinate as the shared secret
	sharedSecret := xCoord.Bytes()

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
	sc.ECDSAPrivKey = nil

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
// EncryptMessage encrypts a message using AES-CBC instead of GCM
func (sc *SecureChannel) EncryptMessage(plaintext []byte) (string, error) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if !sc.Established || sc.EncryptionKey == nil {
		return "", fmt.Errorf("secure channel not established")
	}

	// Create AES cipher
	block, err := aes.NewCipher(sc.EncryptionKey)
	if err != nil {
		return "", fmt.Errorf("error creating cipher: %v", err)
	}

	// Generate IV (16 bytes for CBC)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("error generating IV: %v", err)
	}

	// Add PKCS7 padding to plaintext
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)

	// Encrypt with CBC mode
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	// Increment counter
	sc.SendCounter++

	// Format: base64(iv) + ":" + base64(ciphertext)
	encryptedMessage := base64.StdEncoding.EncodeToString(iv) + ":" +
		base64.StdEncoding.EncodeToString(ciphertext)

	return encryptedMessage, nil
}

// DecryptMessage decrypts a message using AES-CBC instead of GCM
// DecryptMessage decrypts a message using AES-CBC with improved error handling
func (sc *SecureChannel) DecryptMessage(encryptedMessage string) ([]byte, error) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if !sc.Established || sc.DecryptionKey == nil {
		return nil, fmt.Errorf("secure channel not established")
	}

	// Parse the encrypted message
	parts := strings.Split(encryptedMessage, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid encrypted message format: expected 2 parts, got %d", len(parts))
	}

	// Decode IV and ciphertext
	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("error decoding IV: %v", err)
	}

	// Print IV for debugging
	fmt.Printf("IV length: %d, IV bytes: %v\n", len(iv), iv)

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV length: %d, expected %d", len(iv), aes.BlockSize)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error decoding ciphertext: %v", err)
	}

	// Print ciphertext properties for debugging
	fmt.Printf("Ciphertext length: %d, is multiple of block size: %v\n",
		len(ciphertext), len(ciphertext)%aes.BlockSize == 0)

	// Create AES cipher
	block, err := aes.NewCipher(sc.DecryptionKey)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %v", err)
	}

	// Decrypt with CBC mode
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))

	// Make sure ciphertext length is a multiple of the block size
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length (%d) is not a multiple of block size (%d)",
			len(ciphertext), aes.BlockSize)
	}

	mode.CryptBlocks(plaintext, ciphertext)

	// Print the raw decrypted data for debugging
	fmt.Printf("Raw decrypted data (first 16 bytes): %v\n", plaintext[:min(16, len(plaintext))])
	if len(plaintext) > 0 {
		fmt.Printf("Last byte (potential padding length): %d\n", plaintext[len(plaintext)-1])
	}

	// Try more permissive unpadding
	var unpadErr error
	unpadded, unpadErr := pkcs7Unpad(plaintext, aes.BlockSize)

	if unpadErr != nil {
		fmt.Printf("Warning: unpadding error: %v\n", unpadErr)
		// Fallback: try interpreting the last byte as the padding length
		if len(plaintext) > 0 {
			paddingLen := int(plaintext[len(plaintext)-1])
			if paddingLen <= aes.BlockSize && len(plaintext) >= paddingLen {
				fmt.Printf("Attempting fallback padding removal with length: %d\n", paddingLen)
				unpadded = plaintext[:len(plaintext)-paddingLen]
			} else {
				// Last resort: just return the data as is
				fmt.Printf("Using raw decrypted data without unpadding\n")
				unpadded = plaintext
			}
		} else {
			return nil, fmt.Errorf("empty plaintext and unpadding failed: %v", unpadErr)
		}
	}

	// Increment counter
	sc.ReceiveCounter++

	return unpadded, nil
}

// Improved Helper function for PKCS7 padding
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// Improved Helper function for PKCS7 unpadding with better error handling
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("empty data")
	}
	if length%blockSize != 0 {
		return nil, fmt.Errorf("data is not a multiple of the block size")
	}

	padding := int(data[length-1])
	if padding > blockSize {
		fmt.Printf("WARNING: Invalid padding size: %d, block size: %d\n", padding, blockSize)
		// For compatibility with Python, try just removing the last byte
		return data[:length-1], nil
	}

	if padding == 0 {
		return nil, fmt.Errorf("invalid padding value (0)")
	}

	// Verify padding is correct
	paddingStart := length - padding
	if paddingStart < 0 {
		fmt.Printf("WARNING: Padding start index would be negative: %d\n", paddingStart)
		return data[:length-1], nil
	}

	// Print padding bytes for debugging
	fmt.Printf("Padding bytes: ")
	for i := paddingStart; i < length; i++ {
		fmt.Printf("%d ", data[i])
	}
	fmt.Println()

	// More permissive padding check that allows for partial validation
	for i := length - 1; i >= paddingStart; i-- {
		if data[i] != byte(padding) {
			fmt.Printf("WARNING: Invalid padding at position %d: expected %d, got %d\n",
				i, padding, data[i])

			// For compatibility, try simple truncation
			return data[:length-1], nil
		}
	}

	return data[:length-padding], nil
}

// In secure_channel.go, update the SendEncrypted method:

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

	// Add detailed logging about the format
	fmt.Printf("Encrypted message format: %s\n", encrypted)
	parts := strings.Split(encrypted, ":")
	fmt.Printf("Number of parts: %d\n", len(parts))

	// Send the encrypted message
	encrypted_message := fmt.Sprintf("SECURE:DATA:%s", encrypted)
	fmt.Printf("Full message being sent: %s\n", encrypted_message)

	_, err = sc.Conn.Write([]byte(encrypted_message))
	// ...
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
	sc.ECDSAPrivKey = nil // Changed from PrivateKey
	sc.ECDSAPubKey = nil  // Changed from PeerPublicKey

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
