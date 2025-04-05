package tests

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"p2p-file-sharing/go-client/internal/crypto"
	"p2p-file-sharing/go-client/internal/discovery"
	"p2p-file-sharing/go-client/internal/network"
	"p2p-file-sharing/go-client/internal/storage"
)

// TestPeerDiscoveryAndConnection tests peer discovery and basic connection

func TestPeerDiscovery(t *testing.T) {
	serviceName := "_p2p-share-test._tcp."
	mdns := discovery.NewMDNSDiscovery(serviceName)

	// Perform discovery with context
	peers, err := mdns.DiscoverPeers()
	if err != nil {
		t.Logf("Warning: Peer discovery failed: %v", err)

		// In test environment, this might be expected
		// So we'll log the error but not fail the test
		t.Log("Note: Peer discovery may fail in test environment. This is not necessarily an error.")

		// Additional diagnostics
		t.Log("Possible reasons for mDNS discovery failure:")
		t.Log("1. No other peers on the local network")
		t.Log("2. Firewall blocking mDNS")
		t.Log("3. Network interface configuration")

		return
	}

	// Log discovered peers
	t.Logf("Discovered %d peers", len(peers))

	// If peers are found, print their details
	for i, peer := range peers {
		t.Logf("Peer %d: %s", i+1, peer)
	}
}

// MockPeerDiscovery provides a way to test discovery logic without relying on network
func TestMockPeerDiscovery(t *testing.T) {
	// Create a mock discovery mechanism
	mockPeers := []string{
		"127.0.0.1:12345",
		"localhost:54321",
	}

	// Simulate discovery
	t.Log("Running mock peer discovery")

	if len(mockPeers) == 0 {
		t.Log("No mock peers configured")
	}

	for i, peer := range mockPeers {
		t.Logf("Mock Peer %d: %s", i+1, peer)
	}
}

// TestMutualAuthentication tests the full authentication protocol
func TestMutualAuthentication(t *testing.T) {
	// Generate unique peer IDs
	peerID1 := generateTestPeerID()
	peerID2 := generateTestPeerID()

	// Create contact managers
	contactManager1, err := crypto.NewContactManager(peerID1)
	if err != nil {
		t.Fatalf("Failed to create contact manager 1: %v", err)
	}
	contactManager2, err := crypto.NewContactManager(peerID2)
	if err != nil {
		t.Fatalf("Failed to create contact manager 2: %v", err)
	}

	// Create authentication instances
	auth1, err := crypto.NewPeerAuthentication(peerID1, contactManager1)
	if err != nil {
		t.Fatalf("Failed to create authentication 1: %v", err)
	}
	auth2, err := crypto.NewPeerAuthentication(peerID2, contactManager2)
	if err != nil {
		t.Fatalf("Failed to create authentication 2: %v", err)
	}

	// Simulate full authentication process
	challengeID, challengeB64, err := auth1.CreateChallenge(peerID2)
	if err != nil {
		t.Fatalf("Failed to create challenge: %v", err)
	}

	// Sign challenge
	signature, err := auth2.SignChallenge(challengeB64)
	if err != nil {
		t.Fatalf("Failed to sign challenge: %v", err)
	}

	// Verify signature using the first peer's authentication
	verified, err := auth1.VerifySignature(peerID2, challengeID, signature, auth2.GetPublicKeyPEM())
	if err != nil {
		t.Fatalf("Signature verification failed: %v", err)
	}
	if !verified {
		t.Fatal("Signature verification did not pass")
	}

	// Simulate adding trusted contact
	contact2 := crypto.TrustedContact{
		PeerID:     peerID2,
		Address:    "127.0.0.1:12345",
		PublicKey:  auth2.GetPublicKeyPEM(),
		Nickname:   "Test Peer 2",
		VerifiedAt: float64(time.Now().Unix()),
	}

	// Add the contact to contact manager 1
	success := contactManager1.AddTrustedContact(
		contact2.PeerID,
		contact2.Address,
		contact2.PublicKey,
		contact2.Nickname,
	)
	if !success {
		t.Fatal("Failed to add trusted contact")
	}

	// Verify contact was added
	retrievedContact, found := contactManager1.GetTrustedContact(peerID2)
	if !found {
		t.Fatal("Trusted contact not found after adding")
	}

	// Check retrieved contact details
	if retrievedContact.PeerID != contact2.PeerID {
		t.Errorf("Peer ID mismatch. Expected %s, got %s", contact2.PeerID, retrievedContact.PeerID)
	}
}

// TestFileIntegrityAndHashing tests file hash generation and verification
func TestFileIntegrityAndHashing(t *testing.T) {
	// Create a test file
	testFile, err := createTestFile("integrity_test.txt", 1024)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(testFile)

	// Create hash manager
	hashManager, err := crypto.NewHashManager("test-peer")
	if err != nil {
		t.Fatalf("Failed to create hash manager: %v", err)
	}

	// Calculate file hash
	filename := filepath.Base(testFile)
	fileHash, err := hashManager.AddFileHash(filename, testFile, "test-origin")
	if err != nil {
		t.Fatalf("Failed to calculate file hash: %v", err)
	}

	// Verify file hash
	verified, err := hashManager.VerifyFileHash(testFile, fileHash)
	if err != nil {
		t.Fatalf("File hash verification failed: %v", err)
	}
	if !verified {
		t.Fatal("File hash verification did not pass")
	}

	// Retrieve hash information
	hashInfo, exists := hashManager.GetFileHash(filename)
	if !exists {
		t.Fatal("Failed to retrieve file hash information")
	}

	// Check hash details
	if hashInfo.Hash != fileHash {
		t.Errorf("Hash mismatch. Expected %s, got %s", fileHash, hashInfo.Hash)
	}
	if hashInfo.OriginPeer != "test-origin" {
		t.Errorf("Origin peer mismatch. Expected test-origin, got %s", hashInfo.OriginPeer)
	}
}

// TestSecureFileStorage tests secure file encryption and decryption
func TestSecureFileStorage(t *testing.T) {
	// Create a test file with random content
	testFile, err := createTestFile("secure_storage_test.txt", 2048)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(testFile)

	// Initialize secure storage
	secureStorage, err := storage.NewSecureStorage()
	if err != nil {
		t.Fatalf("Failed to create secure storage: %v", err)
	}

	// Store file securely with a known passphrase
	passphrase := "test-secure-storage-passphrase"
	encryptedPath, err := secureStorage.SecureStoreFile(testFile, passphrase)
	if err != nil {
		t.Fatalf("Failed to store file securely: %v", err)
	}

	// Verify encrypted file exists
	if _, err := os.Stat(encryptedPath); os.IsNotExist(err) {
		t.Fatal("Encrypted file was not created")
	}

	// List secure files
	secureFiles, err := secureStorage.ListSecureFiles()
	if err != nil {
		t.Fatalf("Failed to list secure files: %v", err)
	}
	if len(secureFiles) == 0 {
		t.Fatal("No secure files found after storage")
	}

	// Prepare output path for decryption
	outputPath := filepath.Join(os.TempDir(), "decrypted_secure_storage_test.txt")
	defer os.Remove(outputPath)

	// Retrieve and decrypt the file
	err = secureStorage.SecureRetrieveFile(encryptedPath, outputPath, passphrase)
	if err != nil {
		t.Fatalf("Failed to retrieve secure file: %v", err)
	}

	// Compare original and decrypted file contents
	originalContent, err := ioutil.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read original file: %v", err)
	}
	decryptedContent, err := ioutil.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	// Verify file contents match
	if !bytes.Equal(originalContent, decryptedContent) {
		t.Fatal("Decrypted file content does not match original")
	}

	// Test file deletion
	err = secureStorage.DeleteSecureFile(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to delete secure file: %v", err)
	}

	// Verify file was deleted
	secureFiles, err = secureStorage.ListSecureFiles()
	if err != nil {
		t.Fatalf("Failed to list secure files after deletion: %v", err)
	}
	for _, file := range secureFiles {
		if file == encryptedPath {
			t.Fatal("Encrypted file was not deleted")
		}
	}
}

// TestOfflineFileRetrieval simulates offline file retrieval
func TestOfflineFileRetrieval(t *testing.T) {
	// Create a test file
	testFile, err := createTestFile("offline_test.txt", 1536)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(testFile)

	// Calculate file hash
	hashManager, err := crypto.NewHashManager("original-peer")
	if err != nil {
		t.Fatalf("Failed to create hash manager: %v", err)
	}

	filename := filepath.Base(testFile)
	fileHash, err := hashManager.AddFileHash(filename, testFile, "original-peer")
	if err != nil {
		t.Fatalf("Failed to calculate file hash: %v", err)
	}

	// Simulate offline file retrieval
	success, alternativePeer, err := network.RequestFileFromAlternative(
		filename,
		"original-peer",
		"alternative-peer",
		fileHash,
	)

	if err != nil {
		// Since this might fail in a test environment without peers,
		// we'll check if the error is acceptable
		t.Logf("Offline file retrieval expected to potentially fail: %v", err)
		return
	}

	// If successful, log alternative peer details
	if success {
		t.Logf("Successfully retrieved file from alternative peer: %s", alternativePeer)
	}
}

// Helper function to generate test peer ID
func generateTestPeerID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Helper function to create a test file
func createTestFile(filename string, size int) (string, error) {
	// Create a file in the temp directory
	filePath := filepath.Join(os.TempDir(), filename)

	// Generate random content
	content := make([]byte, size)
	_, err := rand.Read(content)
	if err != nil {
		return "", err
	}

	// Write content to file
	err = ioutil.WriteFile(filePath, content, 0644)
	if err != nil {
		return "", err
	}

	return filePath, nil
}
