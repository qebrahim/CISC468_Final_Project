package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// KeyMigration handles the process of migrating to a new key
type KeyMigration struct {
	PeerID         string
	OldPrivateKey  *rsa.PrivateKey
	OldPublicKey   *rsa.PublicKey
	NewPrivateKey  *rsa.PrivateKey
	NewPublicKey   *rsa.PublicKey
	ContactManager *ContactManager
}

// MigrationNotification represents the notification message for key migration
type MigrationNotification struct {
	PeerID        string  `json:"peer_id"`
	OldPublicKey  string  `json:"old_public_key"`
	NewPublicKey  string  `json:"new_public_key"`
	Signature     string  `json:"signature"` // Signature created with old private key
	MigrationTime float64 `json:"migration_time"`
}

// InitiateMigration starts the process of migrating to a new key
func InitiateMigration(peerID string, contactManager *ContactManager) (*KeyMigration, error) {
	// Check if we have valid parameters
	if peerID == "" || contactManager == nil {
		return nil, fmt.Errorf("invalid peer ID or contact manager")
	}

	// Get paths for keys
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("error getting home directory: %v", err)
	}

	keysDir := filepath.Join(homeDir, ".p2p-share", "keys")
	oldPrivateKeyPath := filepath.Join(keysDir, "private.pem")
	oldPublicKeyPath := filepath.Join(keysDir, "public.pem")

	// Create backup directory
	backupDir := filepath.Join(keysDir, "backup", time.Now().Format("20060102_150405"))
	err = os.MkdirAll(backupDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating backup directory: %v", err)
	}

	// Load old keys
	oldPrivateKey, err := LoadPrivateKey(oldPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error loading old private key: %v", err)
	}

	oldPublicKey, err := LoadPublicKey(oldPublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error loading old public key: %v", err)
	}

	// Backup old keys
	oldPrivateKeyBackupPath := filepath.Join(backupDir, "private.pem")
	oldPublicKeyBackupPath := filepath.Join(backupDir, "public.pem")

	err = copyFile(oldPrivateKeyPath, oldPrivateKeyBackupPath)
	if err != nil {
		return nil, fmt.Errorf("error backing up private key: %v", err)
	}

	err = copyFile(oldPublicKeyPath, oldPublicKeyBackupPath)
	if err != nil {
		return nil, fmt.Errorf("error backing up public key: %v", err)
	}

	// Generate new keys
	newPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("error generating new key pair: %v", err)
	}

	// Create migration object
	migration := &KeyMigration{
		PeerID:         peerID,
		OldPrivateKey:  oldPrivateKey,
		OldPublicKey:   oldPublicKey,
		NewPrivateKey:  newPrivateKey,
		NewPublicKey:   &newPrivateKey.PublicKey,
		ContactManager: contactManager,
	}

	return migration, nil
}

// CompleteMigration finalizes the key migration process
func (km *KeyMigration) CompleteMigration() error {
	// Get paths for keys
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error getting home directory: %v", err)
	}

	keysDir := filepath.Join(homeDir, ".p2p-share", "keys")
	privateKeyPath := filepath.Join(keysDir, "private.pem")
	publicKeyPath := filepath.Join(keysDir, "public.pem")

	// Save new keys
	err = savePrivateKey(km.NewPrivateKey, privateKeyPath)
	if err != nil {
		return fmt.Errorf("error saving new private key: %v", err)
	}

	err = savePublicKey(km.NewPublicKey, publicKeyPath)
	if err != nil {
		return fmt.Errorf("error saving new public key: %v", err)
	}

	fmt.Println("✅ New keys generated and saved successfully")
	return nil
}

// savePrivateKey saves a private key to a file
func savePrivateKey(key *rsa.PrivateKey, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// savePublicKey saves a public key to a file
func savePublicKey(key *rsa.PublicKey, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	pubBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}

	return pem.Encode(file, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
}

// GetPublicKeyPEM returns the PEM encoded public key
func GetPublicKeyPEM(key *rsa.PublicKey) string {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return ""
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return string(pubKeyPEM)
}

// SignMessage signs a message with the private key
func SignMessage(key *rsa.PrivateKey, message string) (string, error) {
	fmt.Printf("DEBUG GO - Raw message bytes (hex): %x\n", []byte(message))
	msgHash := sha256.Sum256([]byte(message))
	fmt.Printf("DEBUG GO - Message hash (hex): %x\n", msgHash[:])

	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, msgHash[:], nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// NotifyContacts notifies all trusted contacts about the key migration
func (km *KeyMigration) NotifyContacts() error {
	// Get the public keys in PEM format
	oldPubKeyPEM := GetPublicKeyPEM(km.OldPublicKey)
	newPubKeyPEM := GetPublicKeyPEM(km.NewPublicKey)

	// Get the list of trusted contacts
	contacts := km.ContactManager.GetAllTrustedContacts()

	// Create notification message
	migrationTime := float64(time.Now().Unix())
	// Change this line in NotifyContacts or wherever you create the message
	message := fmt.Sprintf("KEY_MIGRATION:%s:%d", km.PeerID, int64(migrationTime))

	// Add more detailed logging for debugging

	fmt.Printf("DEBUG GO - Message to sign: %s\n", message)

	// Sign the message with the old private key
	signature, err := SignMessage(km.OldPrivateKey, message)
	if err != nil {
		return fmt.Errorf("error signing migration message: %v", err)
	}

	fmt.Printf("DEBUG GO - Base64 signature: %s\n", signature)
	fmt.Printf("DEBUG GO - Old public key: %s\n", GetPublicKeyPEM(km.OldPublicKey))

	// Create notification payload
	notification := MigrationNotification{
		PeerID:        km.PeerID,
		OldPublicKey:  oldPubKeyPEM,
		NewPublicKey:  newPubKeyPEM,
		Signature:     signature,
		MigrationTime: migrationTime,
	}

	notificationJSON, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("error encoding notification: %v", err)
	}

	// Send notification to all contacts
	fmt.Printf("Notifying %d contacts about key migration\n", len(contacts))

	for peerID, contact := range contacts {
		fmt.Printf("Notifying contact %s at %s\n", peerID, contact.Address)

		// Parse address
		parts := strings.Split(contact.Address, ":")
		if len(parts) != 2 {
			fmt.Printf("Invalid address format for contact %s: %s\n", peerID, contact.Address)
			continue
		}

		host := parts[0]
		port := parts[1]

		// Connect to the peer
		conn, err := net.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			fmt.Printf("Error connecting to contact %s: %v\n", peerID, err)
			continue
		}

		// Send notification
		_, err = conn.Write([]byte(fmt.Sprintf("MIGRATE_KEY:%s", notificationJSON)))
		if err != nil {
			fmt.Printf("Error sending notification to contact %s: %v\n", peerID, err)
		} else {
			fmt.Printf("Successfully notified contact %s\n", peerID)
		}

		conn.Close()
	}

	return nil
}

// HandleMigrateKeyMessage processes a key migration notification from a peer
func HandleMigrateKeyMessage(conn net.Conn, addr string, payload string) error {
	// Parse the notification
	var notification MigrationNotification
	err := json.Unmarshal([]byte(payload), &notification)
	if err != nil {
		return fmt.Errorf("error parsing migration notification: %v", err)
	}

	fmt.Printf("\nReceived key migration notification from peer %s\n", notification.PeerID)

	// Verify notification signature
	message := fmt.Sprintf("KEY_MIGRATION:%s:%f", notification.PeerID, notification.MigrationTime)

	// Get the contact
	contact, exists := contactManager.GetTrustedContact(notification.PeerID)
	if !exists {
		return fmt.Errorf("peer %s is not a trusted contact", notification.PeerID)
	}

	// Verify the old public key matches our stored public key
	if contact.PublicKey != notification.OldPublicKey {
		return fmt.Errorf("old public key in notification does not match our stored key for peer %s", notification.PeerID)
	}

	// Verify signature using old public key
	oldPubKey, err := parsePublicKeyPEM(notification.OldPublicKey)
	if err != nil {
		return fmt.Errorf("error parsing old public key: %v", err)
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(notification.Signature)
	if err != nil {
		return fmt.Errorf("error decoding signature: %v", err)
	}

	msgHash := sha256.Sum256([]byte(message))
	err = rsa.VerifyPSS(oldPubKey, crypto.SHA256, msgHash[:], signatureBytes, nil)
	if err != nil {
		return fmt.Errorf("invalid signature in migration notification: %v", err)
	}

	// Valid notification - update the contact
	fmt.Printf("Verified key migration from peer %s\n", notification.PeerID)
	fmt.Printf("Do you want to accept this key migration? (y/n): ")
	var consent string
	fmt.Scanln(&consent)

	if strings.ToLower(consent) != "y" {
		fmt.Printf("Key migration from peer %s rejected\n", notification.PeerID)
		return nil
	}

	// Update the contact with the new public key
	contact.PublicKey = notification.NewPublicKey
	contact.VerifiedAt = notification.MigrationTime
	contact.LastSeen = float64(time.Now().Unix())

	contactManager.SaveContacts()

	fmt.Printf("Updated public key for peer %s\n", notification.PeerID)

	// Send acknowledgment
	ack := map[string]interface{}{
		"peer_id": authentication.PeerID,
		"status":  "accepted",
	}

	ackJSON, err := json.Marshal(ack)
	if err == nil {
		conn.Write([]byte(fmt.Sprintf("MIGRATE_KEY_ACK:%s", ackJSON)))
	}

	return nil
}

// parsePublicKeyPEM parses a PEM encoded public key
func parsePublicKeyPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return pubKey, nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	return nil
}
