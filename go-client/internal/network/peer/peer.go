package peer

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"p2p-file-sharing/go-client/internal/crypto/auth"
	"p2p-file-sharing/go-client/internal/crypto/keys"
	"path/filepath"
	"sync"
	"time"
)

// Peer represents a node in the P2P network
type Peer struct {
	PeerID     string
	Address    string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Auth       *auth.PeerAuthentication
	SharedDir  string

	// Connected peers
	mu             sync.RWMutex
	connectedPeers map[string]string // Map of peer IDs to addresses
}

// FileRequest represents a request for a file
type FileRequest struct {
	FileName  string `json:"file_name"`
	Requester string `json:"requester"`
}

// FileResponse represents a response to a file request
type FileResponse struct {
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	FileHash string `json:"file_hash,omitempty"`
	FileSize int64  `json:"file_size,omitempty"`
}

// NewPeer creates a new peer instance
func NewPeer(peerID, address, keysDir, sharedDir string) (*Peer, error) {
	// Load or generate keys
	privatePath := filepath.Join(keysDir, "private.pem")
	publicPath := filepath.Join(keysDir, "public.pem")

	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey

	// Check if keys exist
	if _, err := os.Stat(privatePath); os.IsNotExist(err) {
		// Generate new keys
		keyPair, err := keys.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate key pair: %w", err)
		}

		privateKey = keyPair.PrivateKey
		publicKey = keyPair.PublicKey

		// Save keys
		if err := keys.SavePrivateKey(privateKey, privatePath); err != nil {
			return nil, fmt.Errorf("failed to save private key: %w", err)
		}

		if err := keys.SavePublicKey(publicKey, publicPath); err != nil {
			return nil, fmt.Errorf("failed to save public key: %w", err)
		}
	} else {
		// Load existing keys
		privateKey, err = keys.LoadPrivateKey(privatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}

		publicKey, err = keys.LoadPublicKey(publicPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load public key: %w", err)
		}
	}

	// Create authentication manager
	authManager := auth.NewPeerAuthentication(peerID, privateKey, publicKey)

	// Create shared directory if it doesn't exist
	if err := os.MkdirAll(sharedDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create shared directory: %w", err)
	}

	return &Peer{
		PeerID:         peerID,
		Address:        address,
		PrivateKey:     privateKey,
		PublicKey:      publicKey,
		Auth:           authManager,
		SharedDir:      sharedDir,
		connectedPeers: make(map[string]string),
	}, nil
}

// Connect establishes a secure connection with another peer
func (p *Peer) Connect(address string) error {
	// Parse address
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	// Connect to peer
	conn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}
	defer conn.Close()

	// Initiate authentication
	authReq, err := p.Auth.InitiateAuthentication()
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}

	// Serialize request
	authReqBytes, err := json.Marshal(authReq)
	if err != nil {
		return fmt.Errorf("failed to marshal auth request: %w", err)
	}

	// Send authentication request
	_, err = conn.Write(authReqBytes)
	if err != nil {
		return fmt.Errorf("failed to send auth request: %w", err)
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	// Parse response
	var authResp auth.AuthResponse
	if err := json.Unmarshal(buffer[:n], &authResp); err != nil {
		return fmt.Errorf("failed to parse auth response: %w", err)
	}

	// For now, we assume we know the peer's public key
	// In a real implementation, we would exchange public keys
	var peerPublicKey *rsa.PublicKey

	// Verify response
	if err := p.Auth.VerifyAuthResponse(&authResp, peerPublicKey); err != nil {
		return fmt.Errorf("auth response verification failed: %w", err)
	}

	// Add to verified peers
	p.Auth.AddVerifiedPeer(authResp.PeerID, peerPublicKey, authResp.DHPublicKey)

	// Add to connected peers
	p.mu.Lock()
	p.connectedPeers[authResp.PeerID] = address
	p.mu.Unlock()

	fmt.Printf("✅ Connected to peer %s at %s\n", authResp.PeerID, address)
	return nil
}

// RequestFile requests a file from a peer
func (p *Peer) RequestFile(peerID, fileName string) error {
	// Check if peer is connected
	p.mu.RLock()
	address, exists := p.connectedPeers[peerID]
	p.mu.RUnlock()

	if !exists {
		return errors.New("peer not connected")
	}

	// Create file request
	request := FileRequest{
		FileName:  fileName,
		Requester: p.PeerID,
	}

	// Serialize request
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal file request: %w", err)
	}

	// Encrypt request
	encryptedRequest, err := p.Auth.EncryptMessage(peerID, requestBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt file request: %w", err)
	}

	// Parse address
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	// Connect to peer
	conn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}
	defer conn.Close()

	// Send request type
	_, err = conn.Write([]byte("FILE_REQUEST"))
	if err != nil {
		return fmt.Errorf("failed to send request type: %w", err)
	}

	// Read acknowledgment
	ack := make([]byte, 3)
	_, err = conn.Read(ack)
	if err != nil {
		return fmt.Errorf("failed to read acknowledgment: %w", err)
	}

	if string(ack) != "ACK" {
		return errors.New("invalid acknowledgment")
	}

	// Send encrypted request
	_, err = conn.Write(encryptedRequest)
	if err != nil {
		return fmt.Errorf("failed to send file request: %w", err)
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Decrypt response
	decryptedResponse, err := p.Auth.DecryptMessage(peerID, buffer[:n])
	if err != nil {
		return fmt.Errorf("failed to decrypt response: %w", err)
	}

	// Parse response
	var response FileResponse
	if err := json.Unmarshal(decryptedResponse, &response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Check response status
	if response.Status != "approved" {
		reason := response.Reason
		if reason == "" {
			reason = "unknown"
		}
		return fmt.Errorf("file request denied: %s", reason)
	}

	// Receive file
	return p.receiveFile(conn, fileName, peerID, response.FileHash)
}

// receiveFile receives a file from a peer
func (p *Peer) receiveFile(conn net.Conn, fileName, peerID, expectedHash string) error {
	// Create file
	filePath := filepath.Join(p.SharedDir, fileName)
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Send ready signal
	_, err = conn.Write([]byte("READY"))
	if err != nil {
		return fmt.Errorf("failed to send ready signal: %w", err)
	}

	// Receive file chunks
	hasher := sha256.New()

	for {
		// Read chunk size
		sizeBuffer := make([]byte, 8)
		_, err := io.ReadFull(conn, sizeBuffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read chunk size: %w", err)
		}

		// Parse chunk size
		chunkSize := 0
		for i := 0; i < 8; i++ {
			chunkSize = (chunkSize << 8) | int(sizeBuffer[i])
		}

		// Check for end marker
		if chunkSize == 0 {
			break
		}

		// Read chunk
		chunk := make([]byte, chunkSize)
		_, err = io.ReadFull(conn, chunk)
		if err != nil {
			return fmt.Errorf("failed to read chunk: %w", err)
		}

		// Decrypt chunk (in a real implementation)
		// For simplicity, we'll skip actual decryption here

		// Update hash
		hasher.Write(chunk)

		// Write to file
		_, err = file.Write(chunk)
		if err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}

		// Send acknowledgment
		_, err = conn.Write([]byte("OK"))
		if err != nil {
			return fmt.Errorf("failed to send acknowledgment: %w", err)
		}
	}

	// Verify file hash
	actualHash := fmt.Sprintf("%x", hasher.Sum(nil))
	if actualHash != expectedHash {
		// Remove file if hash doesn't match
		os.Remove(filePath)
		return fmt.Errorf("file hash mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	fmt.Printf("✅ Successfully received file: %s\n", fileName)
	return nil
}

// HandleFileRequest processes an incoming file request
func (p *Peer) HandleFileRequest(conn net.Conn, encryptedRequest []byte, requesterID string) error {
	// Decrypt request
	decryptedRequest, err := p.Auth.DecryptMessage(requesterID, encryptedRequest)
	if err != nil {
		return fmt.Errorf("failed to decrypt request: %w", err)
	}

	// Parse request
	var request FileRequest
	if err := json.Unmarshal(decryptedRequest, &request); err != nil {
		return fmt.Errorf("failed to parse request: %w", err)
	}

	// Verify requester ID
	if request.Requester != requesterID {
		return errors.New("requester ID mismatch")
	}

	// Check if file exists
	filePath := filepath.Join(p.SharedDir, request.FileName)
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		// Create and encrypt response
		response := FileResponse{
			Status: "denied",
			Reason: "file_not_found",
		}
		responseBytes, _ := json.Marshal(response)
		encryptedResponse, _ := p.Auth.EncryptMessage(requesterID, responseBytes)

		// Send response
		conn.Write(encryptedResponse)
		return errors.New("file not found")
	}

	// Calculate file hash
	fileHash, err := calculateFileHash(filePath)
	if err != nil {
		// Create and encrypt response
		response := FileResponse{
			Status: "denied",
			Reason: "hash_calculation_failed",
		}
		responseBytes, _ := json.Marshal(response)
		encryptedResponse, _ := p.Auth.EncryptMessage(requesterID, responseBytes)

		// Send response
		conn.Write(encryptedResponse)
		return fmt.Errorf("failed to calculate file hash: %w", err)
	}

	// Create response
	response := FileResponse{
		Status:   "approved",
		FileHash: fileHash,
		FileSize: fileInfo.Size(),
	}

	// Serialize and encrypt response
	responseBytes, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	encryptedResponse, err := p.Auth.EncryptMessage(requesterID, responseBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt response: %w", err)
	}

	// Send response
	_, err = conn.Write(encryptedResponse)
	if err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	// Wait for ready signal
	readyBuffer := make([]byte, 5)
	_, err = conn.Read(readyBuffer)
	if err != nil {
		return fmt.Errorf("failed to read ready signal: %w", err)
	}

	if string(readyBuffer) != "READY" {
		return errors.New("invalid ready signal")
	}

	// Send file
	return p.sendFile(conn, filePath, requesterID)
}

// sendFile sends a file to a peer
func (p *Peer) sendFile(conn net.Conn, filePath, recipientID string) error {
	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Send file in chunks
	buffer := make([]byte, 8192)

	for {
		// Read chunk
		n, err := file.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read file: %w", err)
		}

		// Encrypt chunk (in a real implementation)
		// For simplicity, we'll skip actual encryption here
		chunk := buffer[:n]

		// Send chunk size
		sizeBuffer := make([]byte, 8)
		for i := 0; i < 8; i++ {
			sizeBuffer[i] = byte((n >> (8 * (7 - i))) & 0xFF)
		}

		_, err = conn.Write(sizeBuffer)
		if err != nil {
			return fmt.Errorf("failed to send chunk size: %w", err)
		}

		// Send chunk
		_, err = conn.Write(chunk)
		if err != nil {
			return fmt.Errorf("failed to send chunk: %w", err)
		}

		// Wait for acknowledgment
		ackBuffer := make([]byte, 2)
		_, err = conn.Read(ackBuffer)
		if err != nil {
			return fmt.Errorf("failed to read acknowledgment: %w", err)
		}

		if string(ackBuffer) != "OK" {
			return errors.New("invalid acknowledgment")
		}
	}

	// Send end marker
	endMarker := make([]byte, 8)
	_, err = conn.Write(endMarker)
	if err != nil {
		return fmt.Errorf("failed to send end marker: %w", err)
	}

	fmt.Printf("✅ Successfully sent file: %s\n", filepath.Base(filePath))
	return nil
}

// MigrateKeys migrates to new keys for security
// MigrateKeys migrates to new keys for security
func (p *Peer) MigrateKeys() error {
	// Initiate key migration
	migrationData, err := p.Auth.InitiateKeyMigration()
	if err != nil {
		return fmt.Errorf("failed to initiate key migration: %w", err)
	}

	// Get new keys
	newPrivateKey := migrationData["new_private_key"].(*rsa.PrivateKey)
	newPublicKey := migrationData["new_public_key"].(*rsa.PublicKey)
	publicKeyData := migrationData["public_key_data"].([]byte)
	signature := migrationData["signature"].([]byte)

	// Notify all connected peers about the key migration
	p.mu.RLock()
	peers := make([]string, 0, len(p.connectedPeers))
	addresses := make([]string, 0, len(p.connectedPeers))
	for peerID, addr := range p.connectedPeers {
		peers = append(peers, peerID)
		addresses = append(addresses, addr)
	}
	p.mu.RUnlock()

	fmt.Printf("🔄 Notifying %d connected peers of key migration...\n", len(peers))

	// Create migration notification
	migrationNotification := struct {
		Type         string `json:"type"`
		PeerID       string `json:"peer_id"`
		NewPublicKey []byte `json:"new_public_key"`
		Signature    []byte `json:"signature"`
		Timestamp    int64  `json:"timestamp"`
	}{
		Type:         "key_migration",
		PeerID:       p.PeerID,
		NewPublicKey: publicKeyData,
		Signature:    signature,
		Timestamp:    time.Now().Unix(),
	}

	// Send notification to each peer
	for i, peerID := range peers {
		address := addresses[i]

		// Parse address
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			fmt.Printf("⚠️ Invalid address format for peer %s: %v\n", peerID, err)
			continue
		}

		// Connect to peer
		conn, err := net.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			fmt.Printf("⚠️ Failed to connect to peer %s: %v\n", peerID, err)
			continue
		}

		// Encrypt the notification
		notificationBytes, err := json.Marshal(migrationNotification)
		if err != nil {
			fmt.Printf("⚠️ Failed to marshal migration notification for peer %s: %v\n", peerID, err)
			conn.Close()
			continue
		}

		encryptedNotification, err := p.Auth.EncryptMessage(peerID, notificationBytes)
		if err != nil {
			fmt.Printf("⚠️ Failed to encrypt migration notification for peer %s: %v\n", peerID, err)
			conn.Close()
			continue
		}

		// Send notification type
		_, err = conn.Write([]byte("KEY_MIGRATION"))
		if err != nil {
			fmt.Printf("⚠️ Failed to send notification type to peer %s: %v\n", peerID, err)
			conn.Close()
			continue
		}

		// Read acknowledgment
		ack := make([]byte, 3)
		_, err = conn.Read(ack)
		if err != nil {
			fmt.Printf("⚠️ Failed to read acknowledgment from peer %s: %v\n", peerID, err)
			conn.Close()
			continue
		}

		if string(ack) != "ACK" {
			fmt.Printf("⚠️ Invalid acknowledgment from peer %s\n", peerID)
			conn.Close()
			continue
		}

		// Send encrypted notification
		_, err = conn.Write(encryptedNotification)
		if err != nil {
			fmt.Printf("⚠️ Failed to send migration notification to peer %s: %v\n", peerID, err)
			conn.Close()
			continue
		}

		// Read response
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Printf("⚠️ Failed to read response from peer %s: %v\n", peerID, err)
			conn.Close()
			continue
		}

		if string(buffer[:n]) != "OK" {
			fmt.Printf("⚠️ Peer %s rejected key migration: %s\n", peerID, string(buffer[:n]))
		} else {
			fmt.Printf("✅ Peer %s acknowledged key migration\n", peerID)
		}

		conn.Close()
	}

	// Activate new keys
	p.Auth.ActivateNewKeys(newPrivateKey, newPublicKey)
	p.PrivateKey = newPrivateKey
	p.PublicKey = newPublicKey

	// Save new keys
	homePath, _ := os.UserHomeDir()
	keysDir := filepath.Join(homePath, ".p2p-share-go", "keys")

	if err := keys.SavePrivateKey(newPrivateKey, filepath.Join(keysDir, "private.pem")); err != nil {
		return fmt.Errorf("failed to save new private key: %w", err)
	}

	if err := keys.SavePublicKey(newPublicKey, filepath.Join(keysDir, "public.pem")); err != nil {
		return fmt.Errorf("failed to save new public key: %w", err)
	}

	fmt.Println("🔑 Keys successfully migrated and all connected peers have been notified")
	return nil
}

// ListConnectedPeers returns a list of connected peers
func (p *Peer) ListConnectedPeers() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	peerIDs := make([]string, 0, len(p.connectedPeers))
	for peerID := range p.connectedPeers {
		peerIDs = append(peerIDs, peerID)
	}

	return peerIDs
}

// calculateFileHash computes a SHA-256 hash of a file
func calculateFileHash(filePath string) (string, error) {
	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Calculate hash
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// HandleKeyMigration processes a key migration notification from a peer
func (p *Peer) HandleKeyMigration(conn net.Conn, encryptedNotification []byte, senderID string) error {
	// Decrypt notification
	decryptedNotification, err := p.Auth.DecryptMessage(senderID, encryptedNotification)
	if err != nil {
		return fmt.Errorf("failed to decrypt key migration notification: %w", err)
	}

	// Parse notification
	var notification struct {
		Type         string `json:"type"`
		PeerID       string `json:"peer_id"`
		NewPublicKey []byte `json:"new_public_key"`
		Signature    []byte `json:"signature"`
		Timestamp    int64  `json:"timestamp"`
	}

	if err := json.Unmarshal(decryptedNotification, &notification); err != nil {
		return fmt.Errorf("failed to parse key migration notification: %w", err)
	}

	// Verify sender ID
	if notification.PeerID != senderID {
		return errors.New("sender ID mismatch")
	}

	// Check timestamp to prevent replay attacks
	now := time.Now().Unix()
	if now-notification.Timestamp > 300 { // 5 minutes
		return errors.New("key migration notification expired")
	}

	// Get peer's current public key
	p.mu.RLock()
	_, exists := p.connectedPeers[senderID]
	p.mu.RUnlock()

	if !exists {
		return errors.New("peer not connected")
	}

	// Check if peer is in verified peers
	verifiedPeer := p.Auth.GetVerifiedPeer(senderID)
	if verifiedPeer == nil {
		return errors.New("peer not in verified peers")
	}

	oldPublicKey := verifiedPeer.PublicKey

	// Parse new public key
	newPublicKeyInterface, err := x509.ParsePKIXPublicKey(notification.NewPublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse new public key: %w", err)
	}

	newPublicKey, ok := newPublicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid public key format")
	}

	// Verify signature of new public key using old public key
	err = keys.VerifySignature(oldPublicKey, string(notification.NewPublicKey), notification.Signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Update peer's public key
	err = p.Auth.UpdatePeerKey(senderID, newPublicKey)
	if err != nil {
		return fmt.Errorf("failed to update peer key: %w", err)
	}

	fmt.Printf("✅ Updated public key for peer %s after key migration\n", senderID)
	return nil
}
