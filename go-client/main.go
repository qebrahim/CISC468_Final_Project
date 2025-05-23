package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"p2p-file-sharing/go-client/internal/crypto"
	"p2p-file-sharing/go-client/internal/discovery"
	"p2p-file-sharing/go-client/internal/network"
	"p2p-file-sharing/go-client/internal/storage"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Global variables to store state
var connectedPeers map[string]net.Conn
var sharedFiles []string
var hashManager *crypto.HashManager
var contactManager *crypto.ContactManager
var authentication *crypto.PeerAuthentication
var secureStorage *storage.SecureStorage

// Global server port
const serverPort = 12345

// Define this at the top of main.go with other global variables
type SecureFileTransfer struct {
	Filename    string
	Path        string
	Size        int64
	Received    int
	Hash        string
	TransferKey []byte
	File        *os.File
	// New fields
	IsComplete    bool
	StartTime     time.Time
	EndTime       time.Time
	AutoEncrypt   bool
	EncryptedPath string
	StorageKey    []byte
}

var secureFileTransfers = make(map[string]*SecureFileTransfer)
var fileTransferMutex sync.Mutex

// This function handles the end of a file transfer with automatic encryption
func finalizeSecureFileTransfer(transfer *SecureFileTransfer, peerID string) {
	// Close the file
	if transfer.File != nil {
		transfer.File.Close()
		transfer.File = nil
	}

	filename := transfer.Filename
	filepath := transfer.Path
	received := transfer.Received
	expected := transfer.Size
	filehash := transfer.Hash

	// Check if we received all the data
	if int64(received) < expected {
		fmt.Printf("\nWarning: Incomplete file transfer: %d/%d bytes\n", received, expected)
	} else {
		fmt.Printf("\nFile transfer complete: %s\n", filename)
	}

	// Verify hash if available
	if hashManager != nil && filehash != "" {
		verified, err := hashManager.VerifyFileHash(filepath, filehash)
		if err != nil || !verified {
			fmt.Printf("File verification failed: %v\n", err)
		} else {
			fmt.Printf("File integrity verified successfully\n")

			// Add hash to our database
			hashManager.AddFileHash(filename, filepath, peerID)
		}
	}

	// Automatically encrypt the file for secure storage
	if transfer.AutoEncrypt {
		// Generate a random storage key if not provided
		if transfer.StorageKey == nil {
			var err error
			transfer.StorageKey, err = crypto.GenerateRandomKey(32)
			if err != nil {
				fmt.Printf("Error generating storage key: %v\n", err)
				// Continue without encryption if key generation fails
				return
			}
		}

		// Create secure storage if not initialized
		if secureStorage == nil {
			var err error
			secureStorage, err = storage.NewSecureStorage()
			if err != nil {
				fmt.Printf("Error initializing secure storage: %v\n", err)
				return
			}
		}

		// Store the key for future use
		keyPath := filepath + ".key"
		err := ioutil.WriteFile(keyPath, transfer.StorageKey, 0600)
		if err != nil {
			fmt.Printf("Error saving encryption key: %v\n", err)
			return
		}

		// Encrypt the file
		outputPath, err := secureStorage.SecureStoreFile(filepath, string(transfer.StorageKey))
		if err != nil {
			fmt.Printf("Error encrypting file for storage: %v\n", err)
			return
		}

		// Store the encrypted path
		transfer.EncryptedPath = outputPath
		fmt.Printf("File encrypted and stored securely at: %s\n", outputPath)

		// Remove the unencrypted file
		err = os.Remove(filepath)
		if err != nil {
			fmt.Printf("Error removing unencrypted file: %v\n", err)
		}
	}

	// Add to shared files list
	absPath := transfer.Path
	if !contains(sharedFiles, absPath) {
		sharedFiles = append(sharedFiles, absPath)
	}
}

func handleSecureFileEnd(peerID string, payload string) {
	fmt.Printf("\nFile transfer from %s completed\n", peerID)

	fileTransferMutex.Lock()
	transfer, exists := secureFileTransfers[peerID]
	fileTransferMutex.Unlock()

	if !exists {
		fmt.Printf("No active file transfer for peer %s\n", peerID)
		return
	}

	// Set auto-encrypt to true to enable secure storage
	transfer.AutoEncrypt = true

	// Close the file handle to ensure all data is written and the file is ready for encryption
	if transfer.File != nil {
		transfer.File.Close()
		transfer.File = nil
	}

	// Finalize the transfer with automatic encryption
	finalizeSecureFileTransfer(transfer, peerID)

	// Clean up
	fileTransferMutex.Lock()
	delete(secureFileTransfers, peerID)
	fileTransferMutex.Unlock()

	fmt.Printf("\nFile download complete and securely stored\n")
}

// Add a new function to main.go for accessing securely stored files
func accessSecureFile(encryptedPath string, timeout time.Duration) (string, error) {
	// Generate a temporary path for the decrypted file
	tempDir := os.TempDir()
	basename := filepath.Base(encryptedPath)
	originalName := strings.TrimSuffix(basename, ".enc")
	tempPath := filepath.Join(tempDir, originalName)

	// Find the key file
	keyPath := strings.TrimSuffix(encryptedPath, ".enc") + ".key"
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("error reading key file: %v", err)
	}

	// Decrypt the file temporarily
	if secureStorage == nil {
		var initErr error
		secureStorage, initErr = storage.NewSecureStorage()
		if initErr != nil {
			return "", fmt.Errorf("error initializing secure storage: %v", initErr)
		}
	}

	err = secureStorage.TemporaryDecrypt(encryptedPath, tempPath, string(keyData), timeout)
	if err != nil {
		return "", fmt.Errorf("error decrypting file: %v", err)
	}

	fmt.Printf("File temporarily decrypted at %s (will be deleted after %v)\n", tempPath, timeout)
	return tempPath, nil
}

func handleAccessSecureFile(scanner *bufio.Scanner) {
	if secureStorage == nil {
		fmt.Println("Secure storage is not available")
		return
	}

	// List encrypted files
	files, err := secureStorage.ListSecureFiles()
	if err != nil {
		fmt.Printf("Error listing secure files: %v\n", err)
		return
	}

	if len(files) == 0 {
		fmt.Println("No securely stored files found")
		return
	}

	fmt.Println("\nSecurely stored files:")
	for i, file := range files {
		// Extract the original filename by removing the .enc extension and unique ID
		basename := filepath.Base(file)
		nameParts := strings.Split(basename, "_")
		var displayName string
		if len(nameParts) > 1 {
			// Remove the unique ID and '.enc' extension
			displayName = strings.TrimSuffix(nameParts[0], filepath.Ext(nameParts[0])) + filepath.Ext(file)
		} else {
			displayName = basename
		}
		fmt.Printf("%d. %s\n", i+1, displayName)
	}

	fmt.Print("\nEnter file number to access: ")
	scanner.Scan()
	fileIdxStr := scanner.Text()
	fileIdx, err := strconv.Atoi(fileIdxStr)
	if err != nil || fileIdx < 1 || fileIdx > len(files) {
		fmt.Println("Invalid file selection")
		return
	}

	selectedFile := files[fileIdx-1]

	// Find the corresponding key file with more flexible matching
	keyDir := filepath.Join(filepath.Dir(selectedFile), "..", "keys", "secure")

	// Try to find the key file
	var keyFilePath string
	err = filepath.Walk(keyDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check if the filename contains the encrypted filename
		if strings.Contains(info.Name(), filepath.Base(selectedFile)) && strings.HasSuffix(info.Name(), ".key") {
			keyFilePath = path
			return filepath.SkipDir // Stop walking once we find the key
		}
		return nil
	})

	if err != nil || keyFilePath == "" {
		fmt.Printf("Error finding key file for %s: %v\n", selectedFile, err)
		return
	}

	keyData, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		fmt.Printf("Error reading key file: %v\n", err)
		return
	}

	// Ask for output path
	fmt.Print("Enter output path (leave empty for default): ")
	scanner.Scan()
	outputPath := scanner.Text()

	// If no output path specified, create one in the shared directory
	if outputPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Printf("Error getting home directory: %v\n", err)
			return
		}

		// Create shared directory if it doesn't exist
		sharedDir := filepath.Join(homeDir, ".p2p-share", "shared")
		err = os.MkdirAll(sharedDir, 0755)
		if err != nil {
			fmt.Printf("Error creating shared directory: %v\n", err)
			return
		}

		// Extract original filename
		basename := filepath.Base(selectedFile)
		nameParts := strings.Split(basename, "_")
		var outputFilename string
		if len(nameParts) > 1 {
			// Remove the unique ID and '.enc' extension
			outputFilename = strings.TrimSuffix(nameParts[0], filepath.Ext(nameParts[0])) + filepath.Ext(selectedFile)
		} else {
			outputFilename = basename
		}

		outputPath = filepath.Join(sharedDir, outputFilename)
	}

	// Decrypt the file
	err = secureStorage.SecureRetrieveFile(selectedFile, outputPath, string(keyData))
	if err != nil {
		fmt.Printf("Error decrypting file: %v\n", err)
		return
	}

	fmt.Printf("File successfully decrypted to: %s\n", outputPath)
}

func encryptExistingFile(scanner *bufio.Scanner) {
	// List files in shared directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Error getting home directory: %v\n", err)
		return
	}

	sharedDir := filepath.Join(homeDir, ".p2p-share", "shared")
	files, err := os.ReadDir(sharedDir)
	if err != nil {
		fmt.Printf("Error reading shared directory: %v\n", err)
		return
	}

	if len(files) == 0 {
		fmt.Println("No files in shared directory")
		return
	}

	fmt.Println("\nFiles in shared directory:")
	for i, file := range files {
		if !file.IsDir() {
			fmt.Printf("%d. %s\n", i+1, file.Name())
		}
	}

	fmt.Print("\nEnter file number to encrypt: ")
	scanner.Scan()
	fileIdxStr := scanner.Text()
	fileIdx, err := strconv.Atoi(fileIdxStr)
	if err != nil || fileIdx < 1 || fileIdx > len(files) {
		fmt.Println("Invalid file selection")
		return
	}

	selectedFile := files[fileIdx-1]
	if selectedFile.IsDir() {
		fmt.Println("Cannot encrypt a directory")
		return
	}

	filePath := filepath.Join(sharedDir, selectedFile.Name())

	// Initialize secure storage if needed
	if secureStorage == nil {
		secureStorage, err = storage.NewSecureStorage()
		if err != nil {
			fmt.Printf("Error initializing secure storage: %v\n", err)
			return
		}
	}

	// Generate a random storage key
	storageKey, err := crypto.GenerateRandomKey(32)
	if err != nil {
		fmt.Printf("Error generating storage key: %v\n", err)
		return
	}

	// Store the key
	keyPath := filePath + ".key"
	err = ioutil.WriteFile(keyPath, storageKey, 0600)
	if err != nil {
		fmt.Printf("Error saving encryption key: %v\n", err)
		return
	}

	// Encrypt the file
	outputPath, err := secureStorage.SecureStoreFile(filePath, string(storageKey))
	if err != nil {
		fmt.Printf("Error encrypting file: %v\n", err)
		return
	}

	fmt.Printf("File encrypted and stored at: %s\n", outputPath)

	// Ask if user wants to remove the original unencrypted file
	fmt.Print("Remove original unencrypted file? (y/n): ")
	scanner.Scan()
	removeOriginal := scanner.Text()

	if strings.ToLower(removeOriginal) == "y" {
		err = os.Remove(filePath)
		if err != nil {
			fmt.Printf("Error removing original file: %v\n", err)
		} else {
			fmt.Println("Removed original unencrypted file")
		}
	}
}

func main() {
	// Initialize
	// Initialize global variables
	connectedPeers = make(map[string]net.Conn)
	serviceName := "_p2p-share._tcp."
	mdns := discovery.NewMDNSDiscovery(serviceName)

	// Generate a peer ID (first 8 chars of a UUID)
	peerID := generatePeerID()
	fmt.Printf(" Running as peer ID: %s\n", peerID)

	// Initialize hash manager
	var err error
	hashManager, err = crypto.NewHashManager(peerID)
	if err != nil {
		fmt.Printf(" Warning: Failed to initialize hash manager: %v\n", err)
		// Continue without hash verification if failed
	} else {
		fmt.Println(" Hash manager initialized for file verification")
	}

	secureStorage, err = storage.NewSecureStorage()
	if err != nil {
		fmt.Printf("⚠️ Warning: Failed to initialize secure storage: %v\n", err)
		// Continue without secure storage if initialization fails
	} else {
		fmt.Println("✅ Secure storage initialized")
	}

	// Initialize security system
	setupSecurity(peerID)

	// Set up signal handling for graceful shutdown
	setupSignalHandling()

	// Start TCP server to listen for incoming connections
	startServer()

	// Discover initial peers
	fmt.Println(" Browsing for services...")
	peers, err := mdns.DiscoverPeers()
	if err != nil {
		fmt.Printf(" Error discovering peers: %v\n", err)
	} else {
		if len(peers) == 0 {
			fmt.Println(" No peers found initially.")
		} else {
			fmt.Println(" Discovered peers:")
			for _, peer := range peers {
				fmt.Println("   ➡", peer)
				// Automatically connect to discovered peers
				parts := strings.Split(peer, ":")
				host := parts[0]
				port, _ := strconv.Atoi(parts[1])
				connectToPeer(host, port)
			}
		}
	}

	// Start the command-line interface
	runCommandLineInterface()
}

// setupSecurity initializes the authentication and secure channel systems
func setupSecurity(peerID string) {
	// Create keys directory if it doesn't exist
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf(" Warning: Failed to get home directory: %v\n", err)
		return
	}

	keysDir := filepath.Join(homeDir, ".p2p-share", "keys")
	err = os.MkdirAll(keysDir, 0755)
	if err != nil {
		fmt.Printf(" Warning: Failed to create keys directory: %v\n", err)
		return
	}

	privateKeyPath := filepath.Join(keysDir, "private.pem")
	publicKeyPath := filepath.Join(keysDir, "public.pem")

	// Check if key files exist, generate them if not
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		fmt.Println("Generating new key pair...")
		err = crypto.GenerateKeyPair(privateKeyPath, publicKeyPath)
		if err != nil {
			fmt.Printf(" Warning: Failed to generate key pair: %v\n", err)
			return
		}
		fmt.Println(" Key pair generated successfully")
	}

	// Initialize contact manager
	contactManager, err = crypto.NewContactManager(peerID)
	if err != nil {
		fmt.Printf(" Warning: Failed to initialize contact manager: %v\n", err)
		return
	}

	// Initialize authentication system
	authentication, err = crypto.NewPeerAuthentication(peerID, contactManager)
	if err != nil {
		fmt.Printf(" Warning: Failed to initialize authentication system: %v\n", err)
		return
	}

	// Initialize authentication protocol
	// Initialize authentication protocol
	crypto.InitAuthentication(peerID, contactManager, authentication)
	fmt.Println(" Security system initialized")
}

// startServer initializes a TCP server to handle incoming connections
func startServer() {
	// Start server on a separate goroutine
	go func() {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", serverPort))
		if err != nil {
			fmt.Printf(" Error starting server: %v\n", err)
			return
		}
		defer listener.Close()

		fmt.Printf(" Server listening on port %d\n", serverPort)
		// Add this to your main.go or where your application starts
		fmt.Printf("DEBUG: ContactManager initialized with storage path: %s\n", contactManager.StoragePath)

		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Printf(" Error accepting connection: %v\n", err)
				continue
			}

			remoteAddr := conn.RemoteAddr().String()
			fmt.Printf(" Accepted connection from %s\n", remoteAddr)

			// Store connection in connected peers map
			connectedPeers[remoteAddr] = conn

			// Handle connection in a goroutine
			go handlePeerConnection(conn, remoteAddr)
		}
	}()
}

func generatePeerID() string {
	// Generate 4 random bytes
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a timestamp if random generation fails
		return fmt.Sprintf("peer-%d", time.Now().UnixNano())
	}
	// Convert to hex string and return first 8 characters
	return hex.EncodeToString(b)
}

func runCommandLineInterface() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		// Process any pending authentication requests
		processPendingVerifications()

		displayMenu()
		fmt.Print("\nEnter command number: ")

		scanner.Scan()
		choice := scanner.Text()

		switch choice {
		case "1":
			listConnectedPeers()
		case "2":
			requestFile(scanner)
		case "3":
			shareFile(scanner)
		case "4":
			listAvailableFiles()
		case "5":
			authenticatePeer(scanner)
		case "6":
			listTrustedContacts()
		case "7":
			establishSecureChannel(scanner)
		case "8":
			handleSecureStorage(scanner)
		case "9":
			handleKeyMigration(scanner)
		case "10":
			handleAccessSecureFile(scanner)
		case "11":
			encryptExistingFile(scanner) // New option
		case "12":
			fmt.Println("Exiting application...")
			gracefulShutdown()
			return
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}

func displayMenu() {
	fmt.Println("\nAvailable commands:")
	fmt.Println("1. List connected peers")
	fmt.Println("2. Request file")
	fmt.Println("3. Share file")
	fmt.Println("4. List available files")
	fmt.Println("5. Authenticate peer")
	fmt.Println("6. List trusted contacts")
	fmt.Println("7. Establish secure channel")
	fmt.Println("8. Secure storage")
	fmt.Println("9. Key migration")
	fmt.Println("10. Access secure file")
	fmt.Println("11. Encrypt existing file") // New option
	fmt.Println("12. Exit")
}

func listConnectedPeers() {
	fmt.Println("\nConnected peers:")
	if len(connectedPeers) == 0 {
		fmt.Println("No peers connected")
		return
	}

	i := 1
	for peer := range connectedPeers {
		// Display with authentication status if available
		displayName := getDisplayPeerName(peer)
		fmt.Printf("%d. %s\n", i, displayName)
		i++
	}
}

func getDisplayPeerName(peerAddr string) string {
	if contactManager == nil {
		return peerAddr
	}

	// Extract host and use standard port for lookup
	parts := strings.Split(peerAddr, ":")
	if len(parts) < 2 {
		return peerAddr
	}

	standardAddr := fmt.Sprintf("%s:12345", parts[0])
	contact, found := contactManager.GetContactByAddress(standardAddr)

	if found {
		// This is an authenticated peer
		nickname := contact.Nickname
		peerID := contact.PeerID

		if nickname != fmt.Sprintf("Peer-%s", peerID[:6]) {
			return fmt.Sprintf("%s (%s) - %s ✓", nickname, peerID, peerAddr)
		}
		return fmt.Sprintf("%s - %s ✓", peerID, peerAddr)
	}

	return fmt.Sprintf("%s (not authenticated)", peerAddr)
}

func requestFile(scanner *bufio.Scanner) {
	if len(connectedPeers) == 0 {
		fmt.Println("No peers connected")
		return
	}

	// Display the list of peers
	fmt.Println("\nSelect a peer:")
	peersList := make([]string, 0, len(connectedPeers))
	i := 1
	for peer := range connectedPeers {
		displayName := getDisplayPeerName(peer)
		fmt.Printf("%d. %s\n", i, displayName)
		peersList = append(peersList, peer)
		i++
	}

	// Get peer selection
	fmt.Print("Enter peer number: ")
	scanner.Scan()
	peerIdxStr := scanner.Text()
	peerIdx, err := strconv.Atoi(peerIdxStr)
	if err != nil || peerIdx < 1 || peerIdx > len(peersList) {
		fmt.Println("Invalid peer selection")
		return
	}

	// Get the selected peer address
	peerAddr := peersList[peerIdx-1]

	// Get filename
	fmt.Print("Enter filename: ")
	scanner.Scan()
	filename := scanner.Text()

	// Extract host and port from peer address
	parts := strings.Split(peerAddr, ":")
	host := parts[0]
	port, _ := strconv.Atoi(parts[1])

	// Check if using secure channel is an option
	useSecure := false
	if contactManager != nil {
		standardAddr := fmt.Sprintf("%s:12345", host)
		contact, found := contactManager.GetContactByAddress(standardAddr)
		if found {
			fmt.Print(contact)
			fmt.Print("Use encrypted transfer? (y/n): ")
			scanner.Scan()
			useSecureStr := scanner.Text()
			useSecure = strings.ToLower(useSecureStr) == "y"
		}
	}

	// Request the file from the peer
	requestFileFromPeer(host, port, filename, useSecure)
}

func shareFile(scanner *bufio.Scanner) {
	fmt.Print("Enter filename to share: ")
	scanner.Scan()
	filename := scanner.Text()

	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		fmt.Println("File not found")
		return
	}

	// Add to shared files list
	absPath, err := filepath.Abs(filename)
	if err != nil {
		fmt.Printf("Error getting absolute path: %v\n", err)
		return
	}

	sharedFiles = append(sharedFiles, absPath)

	// Calculate and store file hash if hash manager is available
	if hashManager != nil {
		fileHash, err := hashManager.AddFileHash(filepath.Base(filename), absPath, "")
		if err != nil {
			fmt.Printf("Warning: Failed to calculate file hash: %v\n", err)
		} else {
			fmt.Printf("File hash calculated: %s\n", fileHash)
		}
	}

	fmt.Printf("File %s is now available for sharing\n", filename)
}

func authenticatePeer(scanner *bufio.Scanner) {
	if len(connectedPeers) == 0 {
		fmt.Println("No peers connected")
		return
	}

	if contactManager == nil || authentication == nil {
		fmt.Println("Authentication system not initialized")
		return
	}

	// Display the list of peers
	fmt.Println("\nSelect a peer to authenticate:")
	peersList := make([]string, 0, len(connectedPeers))
	i := 1
	for peer := range connectedPeers {
		displayName := getDisplayPeerName(peer)
		fmt.Printf("%d. %s\n", i, displayName)
		peersList = append(peersList, peer)
		i++
	}

	// Get peer selection
	fmt.Print("Enter peer number: ")
	scanner.Scan()
	peerIdxStr := scanner.Text()
	peerIdx, err := strconv.Atoi(peerIdxStr)
	if err != nil || peerIdx < 1 || peerIdx > len(peersList) {
		fmt.Println("Invalid peer selection")
		return
	}

	// Get the selected peer address
	peerAddr := peersList[peerIdx-1]
	fmt.Printf("Initiating authentication with %s...\n", peerAddr)

	// Initiate authentication
	success, err := crypto.InitiateAuthentication(peerAddr)
	if err != nil {
		fmt.Printf("Error initiating authentication: %v\n", err)
		return
	}

	if success {
		fmt.Println("Authentication process started. Follow the prompts to verify the peer.")
	} else {
		fmt.Println("Failed to start authentication process.")
	}
}

func listTrustedContacts() {
	if contactManager == nil {
		fmt.Println("Authentication system not initialized")
		return
	}

	contacts := contactManager.GetAllTrustedContacts()
	if len(contacts) == 0 {
		fmt.Println("No trusted contacts yet.")
		return
	}

	fmt.Println("\nTrusted contacts:")
	i := 1
	for peerID, contact := range contacts {
		nickname := contact.Nickname
		address := contact.Address
		lastSeen := time.Unix(int64(contact.LastSeen), 0).Format("2006-01-02 15:04:05")

		fmt.Printf("%d. %s (%s)\n", i, nickname, peerID)
		fmt.Printf("   Address: %s\n", address)
		fmt.Printf("   Last seen: %s\n", lastSeen)
		fmt.Println()
		i++
	}
}

func establishSecureChannel(scanner *bufio.Scanner) {
	if len(connectedPeers) == 0 {
		fmt.Println("No peers connected")
		return
	}

	if contactManager == nil {
		fmt.Println("Authentication system not initialized")
		return
	}

	// Find authenticated peers
	authenticatedPeers := make([]struct {
		Address string
		Contact crypto.TrustedContact
	}, 0)

	for peerAddr := range connectedPeers {
		// Extract host and use standard port for lookup
		parts := strings.Split(peerAddr, ":")
		if len(parts) < 2 {
			continue
		}

		standardAddr := fmt.Sprintf("%s:12345", parts[0])
		contact, found := contactManager.GetContactByAddress(standardAddr)

		if found {
			authenticatedPeers = append(authenticatedPeers, struct {
				Address string
				Contact crypto.TrustedContact
			}{
				Address: peerAddr,
				Contact: contact,
			})
		}
	}

	if len(authenticatedPeers) == 0 {
		fmt.Println("No authenticated peers available.")
		fmt.Println("You need to authenticate peers before establishing secure channels.")
		return
	}

	fmt.Println("\nSelect a peer to establish a secure encrypted channel:")
	for i, peer := range authenticatedPeers {
		fmt.Printf("%d. %s (%s) - %s\n", i+1, peer.Contact.Nickname, peer.Contact.PeerID, peer.Address)
	}

	// Get peer selection
	fmt.Print("Enter peer number: ")
	scanner.Scan()
	peerIdxStr := scanner.Text()
	peerIdx, err := strconv.Atoi(peerIdxStr)
	if err != nil || peerIdx < 1 || peerIdx > len(authenticatedPeers) {
		fmt.Println("Invalid peer selection")
		return
	}

	// Get the selected peer
	selectedPeer := authenticatedPeers[peerIdx-1]
	peerID := selectedPeer.Contact.PeerID

	// Check if channel already exists
	existingChannel := crypto.GetSecureChannel(peerID)
	if existingChannel != nil && existingChannel.Established {
		fmt.Printf("Secure channel with %s is already established.\n", peerID)
		return
	}

	fmt.Printf("Establishing secure channel with %s...\n", peerID)

	// Establish secure channel
	result, err := crypto.EstablishSecureChannel(peerID, selectedPeer.Address)
	if err != nil {
		fmt.Printf("Error establishing secure channel: %v\n", err)
		return
	}

	switch result["status"] {
	case "established":
		// Keep the connection open by storing it
		_, ok := result["channel"].(*crypto.SecureChannel)
		conn, connOk := result["conn"].(net.Conn)
		if ok && connOk {
			// Update the connection in the global connectedPeers map
			standardAddr := fmt.Sprintf("%s:12345", strings.Split(selectedPeer.Address, ":")[0])
			connectedPeers[standardAddr] = conn

			fmt.Println("Secure channel successfully established.")
		} else {
			fmt.Println("Secure channel established but connection could not be stored.")
		}
	case "initiated":
		fmt.Println("Secure channel initiated. The channel will be established in the background.")
	case "timeout":
		fmt.Println("Secure channel establishment timed out. Please try again.")
	case "error":
		fmt.Printf("Failed to establish secure channel: %v\n", result["message"])
	default:
		fmt.Println("Unexpected status during secure channel establishment.")
	}
}

func listAvailableFiles() {
	if len(connectedPeers) == 0 {
		fmt.Println("No peers connected")
		return
	}

	fmt.Println("\nRequesting file lists from connected peers...")

	// We'll use a wait group to wait for all responses
	var wg sync.WaitGroup

	// Create a channel to collect file list responses
	// Using a buffered channel to avoid deadlocks
	responses := make(chan struct {
		peerAddr string
		fileList string
	}, len(connectedPeers))

	for peerAddr, conn := range connectedPeers {
		fmt.Printf("Requesting files from %s...\n", peerAddr)

		// Add to wait group before starting goroutine
		wg.Add(1)

		// Send file list request and process the response in a goroutine
		go func(addr string, c net.Conn) {
			defer wg.Done()

			// Create a dedicated connection for the file list request
			hostPort := strings.Split(addr, ":")
			if len(hostPort) != 2 {
				fmt.Printf("Invalid peer address format: %s\n", addr)
				return
			}

			host := hostPort[0]
			port, err := strconv.Atoi(hostPort[1])
			if err != nil {
				fmt.Printf("Invalid port in peer address: %s\n", addr)
				return
			}

			// Check if we should use secure channel
			useSecure := false
			var secureChannel *crypto.SecureChannel

			if contactManager != nil {
				standardAddr := fmt.Sprintf("%s:12345", host)
				contact, found := contactManager.GetContactByAddress(standardAddr)
				if found {
					// If we have a secure channel, use it
					secureChannel = crypto.GetSecureChannel(contact.PeerID)
					if secureChannel != nil && secureChannel.Established {
						useSecure = true
					}
				}
			}

			if useSecure && secureChannel != nil {
				// Send file list request through secure channel
				err := secureChannel.SendEncrypted("LIST_FILES", "")
				if err != nil {
					fmt.Printf("Error requesting file list from %s: %v\n", addr, err)
					return
				}

				// For secure channels, responses are handled by the protocol handler
				// in a separate goroutine, so we can't wait for them here
				fmt.Printf("Secure file list request sent to %s\n", addr)
				return
			}

			// Use regular connection for non-secure requests
			newConn, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
			if err != nil {
				fmt.Printf("Error connecting to %s: %v\n", addr, err)
				return
			}
			defer newConn.Close()

			// Send file list request
			_, err = newConn.Write([]byte("LIST_FILES:"))
			if err != nil {
				fmt.Printf("Error requesting file list from %s: %v\n", addr, err)
				return
			}

			// Read response with timeout
			newConn.SetReadDeadline(time.Now().Add(5 * time.Second))

			// Use a simple buffer read instead of waiting for a newline
			buffer := make([]byte, 4096) // Large enough for most file lists
			n, err := newConn.Read(buffer)

			if err != nil {
				fmt.Printf("Error reading file list from %s: %v\n", addr, err)
				return
			}

			// Reset deadline
			newConn.SetReadDeadline(time.Time{})

			// Get the response string
			response := string(buffer[:n])
			fmt.Printf("Raw response from %s: %s\n", addr, response)

			// Check if it's a valid file list response
			if strings.HasPrefix(response, "FILE_LIST:") {
				parts := strings.SplitN(response, ":", 2)
				fileListContent := ""
				if len(parts) > 1 {
					fileListContent = parts[1]
				}

				// Debug output
				fmt.Printf("Parsed file list from %s: %s\n", addr, fileListContent)

				// Send to our channel
				responses <- struct {
					peerAddr string
					fileList string
				}{
					peerAddr: addr,
					fileList: fileListContent,
				}
			} else {
				fmt.Printf("Unexpected response from %s: %s\n", addr, response)
			}
		}(peerAddr, conn)
	}

	// Close the channel when all goroutines are done
	go func() {
		wg.Wait()
		close(responses)
	}()

	// Process all responses
	receivedLists := 0
	for resp := range responses {
		displayFileList(resp.peerAddr, resp.fileList)
		receivedLists++
	}

	if receivedLists == 0 {
		fmt.Println("Did not receive any file lists from peers")
	}

	// Also display local shared files
	localFiles := listLocalSharedFiles()
	if len(localFiles) > 0 {
		fmt.Println("\nLocally shared files:")
		for i, file := range localFiles {
			fmt.Printf("%d. %s\n", i+1, file)
		}
	}
}

// Helper function to list local shared files
func listLocalSharedFiles() []string {
	var files []string

	// Add explicitly shared files
	for _, path := range sharedFiles {
		basename := filepath.Base(path)
		if !contains(files, basename) {
			files = append(files, basename)
		}
	}

	// Check shared directory
	homeDir, err := os.UserHomeDir()
	if err == nil {
		sharedDir := filepath.Join(homeDir, ".p2p-share", "shared")
		entries, err := os.ReadDir(sharedDir)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					if !contains(files, entry.Name()) {
						files = append(files, entry.Name())
					}
				}
			}
		}
	}

	return files
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Helper function to display file list
func displayFileList(peerAddr, fileList string) {
	fmt.Printf("\nFiles available from %s:\n", peerAddr)

	if fileList == "" {
		fmt.Println("  No files available")
		return
	}

	// Check for the separator character to determine the format
	var fileEntries []string

	if strings.Contains(fileList, ";") {
		// New format with multiple file entries separated by semicolons
		fileEntries = strings.Split(fileList, ";")
	} else if strings.Contains(fileList, ",") {
		// Single file entry or old format
		// Check if it contains exactly two commas, which would indicate a file,hash,size triplet
		commaCount := strings.Count(fileList, ",")
		if commaCount == 2 {
			// This is likely a single file entry with hash and size
			fileEntries = []string{fileList}
		} else {
			// Old format (comma-separated filenames only)
			fileEntries = strings.Split(fileList, ",")
		}
	} else {
		// Single file with no metadata
		fileEntries = []string{fileList}
	}

	if len(fileEntries) == 0 || (len(fileEntries) == 1 && fileEntries[0] == "") {
		fmt.Println("  No files available")
		return
	}

	for i, entry := range fileEntries {
		if entry == "" {
			continue
		}

		// Check if entry contains file metadata
		if strings.Count(entry, ",") == 2 {
			// Parse file,hash,size triplet
			fileParts := strings.Split(entry, ",")
			filename := fileParts[0]
			hash := fileParts[1]
			size := fileParts[2]

			// Format output
			sizeStr := ""
			if size != "" {
				sizeInt, err := strconv.ParseInt(size, 10, 64)
				if err == nil {
					sizeStr = fmt.Sprintf(" (%d bytes)", sizeInt)
				}
			}

			verifiedStr := ""
			if hash != "" {
				verifiedStr = " [verifiable]"
			}

			fmt.Printf("  %d. %s%s%s\n", i+1, filename, sizeStr, verifiedStr)

			// Store hash information if hash manager is available
			if hashManager != nil && hash != "" && filename != "" {
				sizeInt, _ := strconv.ParseInt(size, 10, 64)

				hashManager.Hashes[filename] = crypto.FileHashInfo{
					Hash:         hash,
					Size:         sizeInt,
					OriginPeer:   peerAddr,
					LastVerified: float64(time.Now().Unix()),
				}
			}
		} else {
			// Single filename without metadata
			fmt.Printf("  %d. %s\n", i+1, entry)
		}
	}

	// Save updated hashes
	if hashManager != nil {
		hashManager.SaveHashes()
	}
}

func connectToPeer(address string, port int) {
	// Create full address with port
	fullAddress := net.JoinHostPort(address, fmt.Sprintf("%d", port))

	// Check if already connected
	if _, exists := connectedPeers[fullAddress]; exists {
		fmt.Printf("Already connected to %s\n", fullAddress)
		return
	}

	fmt.Printf("🔌 Attempting to connect to %s\n", fullAddress)

	// Establish TCP connection
	conn, err := net.Dial("tcp", fullAddress)
	if err != nil {
		fmt.Printf(" Connection failed: %v\n", err)
		return
	}

	fmt.Println(" Connection established!")

	// Store connection in map
	connectedPeers[fullAddress] = conn

	// Start a goroutine to handle incoming messages from this peer
	go handlePeerConnection(conn, fullAddress)
}

func handlePeerConnection(conn net.Conn, peerAddr string) {
	defer func() {
		conn.Close()
		delete(connectedPeers, peerAddr)
		fmt.Printf("Disconnected from %s\n", peerAddr)
	}()

	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Printf("Error reading from %s: %v\n", peerAddr, err)
			return
		}

		message := string(buffer[:n])
		fmt.Printf(" Received from %s: %s\n", peerAddr, message)

		// Parse and process the message
		fmt.Printf("DEBUG: Raw message: %s\n", message)
		parts := strings.SplitN(message, ":", 2)
		if len(parts) < 2 {
			fmt.Printf("Invalid message format from %s\n", peerAddr)
			continue
		}

		command := parts[0]
		fmt.Printf("DEBUG: Identified command: %s\n", command)

		// Parse peer address for standardized authentication checks
		hostPort := strings.Split(peerAddr, ":")
		if len(hostPort) != 2 {
			fmt.Printf("Invalid peer address format: %s\n", peerAddr)
			continue
		}
		standardAddr := fmt.Sprintf("%s:12345", hostPort[0])

		// Check if this is an authentication message
		if command == "AUTH" {
			// Process authentication message
			if len(parts) > 1 {
				err := crypto.HandleAuthMessage(conn, peerAddr, message)
				if err != nil {
					fmt.Printf("Error handling auth message: %v\n", err)
				}
			}
			continue
		}

		// Check if this is a secure channel message

		// For sensitive operations, check if peer is authenticated
		if command == "REQUEST_FILE" || command == "LIST_FILES" {
			// Only check if auth system is active
			if contactManager != nil && authentication != nil {
				if !crypto.CheckPeerAuthenticated(standardAddr) {
					fmt.Printf("Unauthenticated access attempt from %s\n", peerAddr)
					conn.Write([]byte("ERR:AUTHENTICATION_REQUIRED"))
					continue
				}
			}
		}
		// In the handlePeerConnection function, modify the section that handles secure messages
		if command == "SECURE" {
			// Process secure channel message
			result, err := crypto.HandleSecureMessage(conn, peerAddr, message)
			if err != nil {
				fmt.Printf("Error handling secure message: %v\n", err)
				continue
			}

			// Add more detailed logging to understand what we received
			fmt.Printf("DEBUG: Secure message result: %+v\n", result)

			if result != nil {
				if result["status"] == "message_received" {
					// Get message details
					messageType, typeOk := result["type"].(string)
					payload, payloadOk := result["payload"].(string)
					peerID, peerOk := result["peer_id"].(string)

					if !typeOk || !payloadOk || !peerOk {
						fmt.Printf("Invalid secure message format\n")
						continue
					}

					fmt.Printf("DEBUG: Processing secure message: Type=%s, PeerID=%s, Payload=%s\n", messageType, peerID, payload)

					if messageType == "REQUEST_FILE" {
						// Handle file request
						fmt.Printf("DEBUG: Received secure file request for %s from peer %s\n", payload, peerID)

						// Get secure channel for this peer
						secureChannel := crypto.GetSecureChannel(peerID)
						if secureChannel == nil {
							fmt.Printf("ERROR: No secure channel found for peer %s despite receiving secure message\n", peerID)
							continue
						}

						// Find the file
						filename := payload
						filePath := findSharedFile(filename)
						if filePath == "" {
							fmt.Printf("ERROR: File %s not found for secure transfer\n", filename)
							secureChannel.SendEncrypted("ERROR", "FILE_NOT_FOUND")
							continue
						}

						// Calculate hash if available
						fileHash := ""
						if hashManager != nil {
							hashInfo, exists := hashManager.GetFileHash(filename)
							if exists {
								fileHash = hashInfo.Hash
							} else {
								// Calculate hash
								var err error
								fileHash, err = hashManager.AddFileHash(filename, filePath, "")
								if err != nil {
									fmt.Printf("WARNING: Failed to calculate hash for %s: %v\n", filename, err)
								}
							}
						}

						fmt.Printf("DEBUG: Sending file %s securely to peer %s (hash: %s)\n", filePath, peerID, fileHash)
						// Use your secure file sending function
						go sendFileSecure(secureChannel, filePath, fileHash)
					} else if messageType == "LIST_FILES" {
						// Handle file list request through secure channel
						fmt.Printf("DEBUG: Received secure file list request from peer %s\n", peerID)

						// Get secure channel
						secureChannel := crypto.GetSecureChannel(peerID)
						if secureChannel == nil {
							fmt.Printf("ERROR: No secure channel found for peer %s despite receiving secure message\n", peerID)
							continue
						}

						// Get file list
						fileList := getFileListString()
						fmt.Printf("DEBUG: Sending file list securely: %s\n", fileList)
						secureChannel.SendEncrypted("FILE_LIST", fileList)
					} else if messageType == "FILE_HEADER" || messageType == "FILE_CHUNK" || messageType == "FILE_END" {
						// Handle file transfer messages
						handleSecureFileTransfer(peerID, messageType, payload)
					} else {
						fmt.Printf("Unknown secure message type: %s\n", messageType)
					}
				} else if result["status"] == "secure_channel_established" {
					// New code to handle the secure channel established case
					fmt.Printf("Secure channel established with peer %s\n", result["peer_id"])
				} else {
					fmt.Printf("Unhandled secure message status: %s\n", result["status"])
				}
				continue
			}
		}

		// Process regular commands
		switch command {
		case "REQUEST_FILE":
			if len(parts) > 1 {
				filename := parts[1]
				handleFileRequest(conn, peerAddr, filename)
			} else {
				conn.Write([]byte("ERR:INVALID_REQUEST"))
			}

		case "LIST_FILES":
			handleListFilesRequest(conn)

		case "ESTABLISH_SECURE":
			// Handle request to establish secure channel
			if contactManager != nil && authentication != nil {
				if !crypto.CheckPeerAuthenticated(standardAddr) {
					conn.Write([]byte("ERR:AUTHENTICATION_REQUIRED"))
					continue
				}

				// Get the peer's ID
				contact, found := contactManager.GetContactByAddress(standardAddr)
				if !found {
					conn.Write([]byte("ERR:PEER_NOT_FOUND"))
					continue
				}

				peerID := contact.PeerID

				// Inform the user
				fmt.Printf("\nPeer %s requested to establish a secure encrypted channel.\n", peerID)
				fmt.Print("Do you want to accept? (y/n): ")

				// In a real implementation, you'd wait for user input
				// For now, auto-accept
				fmt.Println("y (auto-accepted)")

				// Respond with acceptance
				conn.Write([]byte("ESTABLISH_SECURE:ACCEPTED"))

				fmt.Printf("Accepted secure channel request from %s\n", peerID)
			} else {
				conn.Write([]byte("ERR:AUTHENTICATION_NOT_AVAILABLE"))
			}
		case "OFFLINE_FILE_REQUEST":
			if len(parts) > 1 {
				network.HandleOfflineFileRequest(conn, parts[1])
			} else {
				conn.Write([]byte("ERR:INVALID_REQUEST"))
			}

		default:
			fmt.Printf("Unknown command from %s: %s\n", peerAddr, command)
			conn.Write([]byte("ERR:UNKNOWN_COMMAND"))
		}
	}
}

func handleFileRequest(conn net.Conn, peerAddr, filename string) {
	// Check if file exists in shared files
	found := false
	var filePath string

	// First check if the requested file matches any shared file by basename
	isAlreadyShared := false
	basename := filepath.Base(filename)
	for _, path := range sharedFiles {
		if filepath.Base(path) == basename {
			isAlreadyShared = true
			break
		}
	}

	// If not found in shared files, check in the default shared directory
	if !found {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			sharedPath := filepath.Join(homeDir, ".p2p-share", "shared", basename)
			if _, err := os.Stat(sharedPath); err == nil {
				found = true
				filePath = sharedPath
			}
		}
	}

	// If file not found, send error
	if !found {
		conn.Write([]byte("ERR:FILE_NOT_FOUND"))
		return
	}

	// Get peer information for display
	displayPeer := peerAddr
	if contactManager != nil {
		hostPort := strings.Split(peerAddr, ":")
		if len(hostPort) == 2 {
			standardAddr := fmt.Sprintf("%s:12345", hostPort[0])
			contact, found := contactManager.GetContactByAddress(standardAddr)
			if found {
				displayPeer = fmt.Sprintf("%s (%s)", contact.Nickname, contact.PeerID)
			}
		}
	}

	// Also check if file is in the default shared directory
	if !isAlreadyShared {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			sharedPath := filepath.Join(homeDir, ".p2p-share", "shared", basename)
			if _, err := os.Stat(sharedPath); err == nil {
				isAlreadyShared = true
			}
		}
	}

	// Skip asking for consent if the file is already shared
	consent := "n"
	if isAlreadyShared {
		fmt.Printf("\nAuto-sharing file '%s' with %s (file is already in shared list)\n",
			filename, displayPeer)
		consent = "y"
	} else {
		// Ask for user consent for files not in the shared list
		fmt.Printf("\nAllow %s to download %s? (y/n): ", displayPeer, filename)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		consent = scanner.Text()
	}

	if strings.ToLower(consent) != "y" {
		conn.Write([]byte("ERR:REQUEST_DENIED"))
		fmt.Printf("File request denied\n")
		return
	}

	// Calculate file hash if hash manager is available
	var fileHash string
	if hashManager != nil {
		hashInfo, exists := hashManager.GetFileHash(basename)
		if exists {
			fileHash = hashInfo.Hash
		} else {
			// Calculate and store hash
			var err error
			fileHash, err = hashManager.AddFileHash(basename, filePath, "")
			if err != nil {
				fmt.Printf("Warning: Failed to calculate file hash: %v\n", err)
			}
		}
	}

	// Check if the peer has a secure channel
	var secureChannel *crypto.SecureChannel
	if contactManager != nil {
		hostPort := strings.Split(peerAddr, ":")
		if len(hostPort) == 2 {
			standardAddr := fmt.Sprintf("%s:12345", hostPort[0])
			contact, found := contactManager.GetContactByAddress(standardAddr)
			if found {
				secureChannel = crypto.GetSecureChannel(contact.PeerID)
			}
		}
	}

	// Use secure channel if available and established
	if secureChannel != nil && secureChannel.Established {
		// Send the file through secure channel
		sendFileSecure(secureChannel, filePath, fileHash)
	} else {
		// Send the file through normal connection
		sendFileRegular(conn, filePath, fileHash)
	}
}

func sendFileRegular(conn net.Conn, filePath, fileHash string) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		conn.Write([]byte(fmt.Sprintf("ERR:FILE_OPEN_FAILED:%s", err.Error())))
		return
	}
	defer file.Close()

	// Get file info for size
	fileInfo, err := file.Stat()
	if err != nil {
		conn.Write([]byte(fmt.Sprintf("ERR:FILE_STAT_FAILED:%s", err.Error())))
		return
	}

	fileSize := fileInfo.Size()

	// Send file header with hash information if available
	var header string
	if fileHash != "" {
		header = fmt.Sprintf("FILE_DATA:%s:%d:%s:", filepath.Base(filePath), fileSize, fileHash)
	} else {
		header = fmt.Sprintf("FILE_DATA:%s:%d:", filepath.Base(filePath), fileSize)
	}

	_, err = conn.Write([]byte(header))
	if err != nil {
		fmt.Printf("Error sending file header: %v\n", err)
		return
	}

	// Send file data in chunks
	buffer := make([]byte, 4096)
	bytesSent := 0

	for {
		bytesRead, err := file.Read(buffer)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			fmt.Printf("Error reading file: %v\n", err)
			return
		}

		if bytesRead == 0 {
			break
		}

		_, err = conn.Write(buffer[:bytesRead])
		if err != nil {
			fmt.Printf("Error sending file data: %v\n", err)
			return
		}

		bytesSent += bytesRead

		// Display progress
		percentComplete := float64(bytesSent) / float64(fileSize) * 100
		if bytesSent%40960 == 0 { // Log every ~40KB
			fmt.Printf("Sending: %.1f%%\n", percentComplete)
		}
	}

	fmt.Printf("File %s sent successfully\n", filepath.Base(filePath))
}

// Add this to main.go in the sendFileSecure function to enhance logging
// Find the sendFileSecure function (around line 3300-3400 in main.go)

func sendFileSecure(channel *crypto.SecureChannel, filePath, fileHash string) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		channel.SendEncrypted("ERROR", fmt.Sprintf("FILE_OPEN_FAILED:%s", err.Error()))
		return
	}
	defer file.Close()

	// Get file info for size
	fileInfo, err := file.Stat()
	if err != nil {
		channel.SendEncrypted("ERROR", fmt.Sprintf("FILE_STAT_FAILED:%s", err.Error()))
		return
	}

	fileSize := fileInfo.Size()
	filename := filepath.Base(filePath)

	// Generate a random encryption key for this transfer
	transferKey := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(transferKey); err != nil {
		channel.SendEncrypted("ERROR", fmt.Sprintf("ENCRYPTION_FAILED:%s", err.Error()))
		return
	}

	// Enhanced debug logging - log key and file info
	fmt.Printf("DEBUG: Sending file '%s' securely (size: %d bytes)\n", filename, fileSize)
	fmt.Printf("DEBUG: Transfer key length: %d bytes\n", len(transferKey))
	fmt.Printf("DEBUG: Transfer key (hex): %x\n", transferKey)

	// Send file header with hash info and encryption key
	header := map[string]interface{}{
		"filename": filename,
		"size":     fileSize,
		"key":      base64.StdEncoding.EncodeToString(transferKey), // Send key securely
	}
	if fileHash != "" {
		header["hash"] = fileHash
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		fmt.Printf("Error encoding file header: %v\n", err)
		return
	}

	fmt.Printf("DEBUG: Sending FILE_HEADER: %s\n", string(headerJSON))
	err = channel.SendEncrypted("FILE_HEADER", string(headerJSON))
	if err != nil {
		fmt.Printf("Error sending file header: %v\n", err)
		return
	}

	// Read and encrypt the file in chunks
	buffer := make([]byte, 4096)
	bytesSent := 0

	for {
		bytesRead, err := file.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Printf("Error reading file: %v\n", err)
			return
		}

		if bytesRead == 0 {
			break
		}

		// Encrypt this chunk
		chunk := buffer[:bytesRead]
		fmt.Printf("DEBUG: Encrypting chunk of size %d bytes\n", len(chunk))

		encryptedChunk, err := crypto.Encrypt(chunk, transferKey)
		if err != nil {
			fmt.Printf("Error encrypting chunk: %v\n", err)
			channel.SendEncrypted("ERROR", fmt.Sprintf("ENCRYPTION_FAILED:%s", err.Error()))
			return
		}

		// Encode encrypted chunk as base64
		chunkB64 := base64.StdEncoding.EncodeToString(encryptedChunk)
		fmt.Printf("DEBUG: Sending encrypted chunk (base64 length: %d)\n", len(chunkB64))

		// Send the encrypted chunk
		err = channel.SendEncrypted("FILE_CHUNK", chunkB64)
		if err != nil {
			fmt.Printf("Error sending file chunk: %v\n", err)
			return
		}

		bytesSent += bytesRead

		// Display progress
		percentComplete := float64(bytesSent) / float64(fileSize) * 100
		if bytesSent%40960 == 0 { // Log every ~40KB
			fmt.Printf("Sending (secure): %.1f%%\n", percentComplete)
		}
	}

	// Send end of file marker
	fmt.Printf("DEBUG: Sending FILE_END marker for file %s\n", filename)
	err = channel.SendEncrypted("FILE_END", filename)
	if err != nil {
		fmt.Printf("Error sending end of file marker: %v\n", err)
		return
	}

	// Add small delay to ensure last packet is sent
	time.Sleep(100 * time.Millisecond)

	fmt.Printf("File %s sent securely (%d bytes in %d chunks)\n", filename, bytesSent, bytesSent/4096+1)
}

// Enhanced version of handleSecureFileTransfer to fix potential issues
// This function should be in main.go (around line 1500-1600)

func handleSecureFileTransfer(peerID string, messageType string, payload string) {
	// Access the global transfer state map
	transfer, exists := secureFileTransfers[peerID]

	fmt.Printf("DEBUG: Received secure file message: Type=%s, Peer=%s, Payload length=%d\n",
		messageType, peerID, len(payload))

	if messageType == "FILE_HEADER" {
		// Process a file header which initiates a new transfer
		var header map[string]interface{}
		err := json.Unmarshal([]byte(payload), &header)
		if err != nil {
			fmt.Printf("Error parsing file header: %v\n", err)
			return
		}

		// Extract information from the header
		filename, ok := header["filename"].(string)
		if !ok {
			fmt.Printf("Missing filename in file header\n")
			return
		}

		// Size might be float64 in JSON
		var fileSize int64
		switch size := header["size"].(type) {
		case float64:
			fileSize = int64(size)
		case int64:
			fileSize = size
		case json.Number:
			fileSize, _ = size.Int64()
		default:
			fmt.Printf("Invalid file size type: %T\n", header["size"])
			return
		}

		// Extract optional hash
		fileHash := ""
		if hash, ok := header["hash"].(string); ok {
			fileHash = hash
		}

		// Extract encryption key if present
		var transferKey []byte
		if keyB64, ok := header["key"].(string); ok {
			transferKey, err = base64.StdEncoding.DecodeString(keyB64)
			if err != nil {
				fmt.Printf("Error decoding transfer key: %v\n", err)
			} else {
				fmt.Printf("DEBUG: Received encryption key for file transfer (len: %d) -> %x\n",
					len(transferKey), transferKey[:8])
			}
		}

		// Create download directory if needed
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Printf("Error getting home directory: %v\n", err)
			return
		}
		downloadDir := filepath.Join(homeDir, ".p2p-share", "shared")
		os.MkdirAll(downloadDir, 0755)

		// Create file to save the download
		filePath := filepath.Join(downloadDir, filename)
		file, err := os.Create(filePath)
		if err != nil {
			fmt.Printf("Error creating file: %v\n", err)
			return
		}

		// Initialize transfer object
		secureFileTransfers[peerID] = &SecureFileTransfer{
			Filename:    filename,
			Path:        filePath,
			Size:        fileSize,
			Received:    0,
			Hash:        fileHash,
			TransferKey: transferKey,
			File:        file,
			IsComplete:  false,
			StartTime:   time.Now(),
		}

		fmt.Printf("DEBUG: Starting secure file transfer: %s (%d bytes)\n", filename, fileSize)

	} else if messageType == "FILE_CHUNK" {
		// Process a file chunk
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

		fmt.Printf("DEBUG: Received encrypted chunk of size %d bytes\n", len(encryptedChunk))

		var chunk []byte
		// Decrypt the chunk if we have an encryption key
		if transfer.TransferKey != nil {
			chunk, err = crypto.Decrypt(encryptedChunk, transfer.TransferKey)
			if err != nil {
				fmt.Printf("DEBUG: Error decrypting chunk: %v\n", err)
				fmt.Printf("DEBUG: Encrypted chunk first bytes: %x\n", encryptedChunk[:16])
				fmt.Printf("DEBUG: Key used for decryption: %x\n", transfer.TransferKey[:16])

			} else {
				fmt.Printf("DEBUG: Chunk decryption successful (size: %d bytes)\n", len(chunk))
			}
		} else {
			// No encryption key, use raw data (for backward compatibility)
			chunk = encryptedChunk
			fmt.Printf("DEBUG: No encryption key, using raw chunk data\n")
		}

		// Write the chunk to file
		_, err = transfer.File.Write(chunk)
		if err != nil {
			fmt.Printf("Error writing file chunk: %v\n", err)
			return
		}

		transfer.Received += len(chunk)

		// Display progress
		percentComplete := float64(transfer.Received) / float64(transfer.Size) * 100
		fmt.Printf("Receiving (secure): %.1f%% (%d/%d bytes)\n",
			percentComplete, transfer.Received, transfer.Size)

	} else if messageType == "FILE_END" {
		// Process end of file marker
		if !exists {
			fmt.Printf("No active file transfer for peer %s\n", peerID)
			return
		}

		// Close the file
		if transfer.File != nil {
			transfer.File.Close()
			transfer.File = nil
		}

		transfer.EndTime = time.Now()
		transfer.IsComplete = true
		duration := transfer.EndTime.Sub(transfer.StartTime)

		// Verify the transfer is complete
		if int64(transfer.Received) < transfer.Size {
			fmt.Printf("Warning: Incomplete file transfer for %s (%d/%d bytes, %.1f%%)\n",
				transfer.Filename, transfer.Received, transfer.Size,
				float64(transfer.Received)/float64(transfer.Size)*100)
		} else {
			fmt.Printf("File transfer complete: %s (%d bytes in %v)\n",
				transfer.Filename, transfer.Size, duration)
		}

		// Verify hash if available
		if transfer.Hash != "" && hashManager != nil {
			verified, err := hashManager.VerifyFileHash(transfer.Path, transfer.Hash)
			if err != nil || !verified {
				fmt.Printf("File verification failed: %v\n", err)
			} else {
				fmt.Printf("File integrity verified successfully\n")

				// Add hash to our database
				hashManager.AddFileHash(transfer.Filename, transfer.Path, peerID)
			}
		}

		// Add to shared files
		absPath, _ := filepath.Abs(transfer.Path)
		if !contains(sharedFiles, absPath) {
			sharedFiles = append(sharedFiles, absPath)
			fmt.Printf("Added %s to shared files list\n", absPath)
		}

		// Ensure the file is readable
		fileInfo, err := os.Stat(transfer.Path)
		if err != nil {
			fmt.Printf("Error checking file: %v\n", err)
		} else {
			fmt.Printf("File saved as: %s (size: %d bytes, mode: %s)\n",
				transfer.Path, fileInfo.Size(), fileInfo.Mode().String())
		}

		// Clean up
		delete(secureFileTransfers, peerID)
	} else {
		fmt.Printf("Unknown secure file message type: %s\n", messageType)
	}
}

func handleListFilesRequest(conn net.Conn) {
	// Collect filenames from all shared files
	var fileList []string

	// Add explicitly shared files
	for _, path := range sharedFiles {
		fileList = append(fileList, filepath.Base(path))
	}

	// Check for files in the shared directory
	homeDir, err := os.UserHomeDir()
	if err == nil {
		sharedDir := filepath.Join(homeDir, ".p2p-share", "shared")
		files, err := os.ReadDir(sharedDir)
		if err == nil {
			for _, file := range files {
				if !file.IsDir() {
					fileList = append(fileList, file.Name())
				}
			}
		}
	}

	// Generate response based on hash availability
	var response string
	if hashManager != nil {
		// Get hash information for the files
		hashInfo := hashManager.GetFileHashesAsString(fileList)
		response = fmt.Sprintf("FILE_LIST:%s", hashInfo)
	} else {
		// No hashes available, use comma-separated list
		response = fmt.Sprintf("FILE_LIST:%s", strings.Join(fileList, ","))
	}

	// Send the file list
	_, err = conn.Write([]byte(response))
	if err != nil {
		fmt.Printf("Error sending file list: %v\n", err)
	}
}

func requestFileFromPeer(host string, port int, filename string, useSecure bool) {
	// Check if using secure channel is an option
	var secureChannel *crypto.SecureChannel

	if useSecure && contactManager != nil {
		standardAddr := fmt.Sprintf("%s:12345", host)
		contact, found := contactManager.GetContactByAddress(standardAddr)
		if found {
			// Check if we already have a secure channel
			secureChannel = crypto.GetSecureChannel(contact.PeerID)
			if secureChannel == nil || !secureChannel.Established {
				// Try to establish a secure channel
				fmt.Printf("Establishing secure channel with %s...\n", contact.PeerID)

				// First establish a regular connection to request secure channel
				sock, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
				if err != nil {
					fmt.Printf("Error connecting to %s: %v\n", host, err)
					fmt.Println("Falling back to regular connection")
					useSecure = false
				} else {
					// Send request to establish secure channel
					_, err = sock.Write([]byte("ESTABLISH_SECURE:"))
					if err != nil {
						fmt.Printf("Error requesting secure channel: %v\n", err)
						fmt.Println("Falling back to regular connection")
						useSecure = false
					} else {
						// Wait for response
						buffer := make([]byte, 1024)
						n, err := sock.Read(buffer)
						if err != nil {
							fmt.Printf("Error reading response: %v\n", err)
							fmt.Println("Falling back to regular connection")
							useSecure = false
						} else {
							response := string(buffer[:n])
							if response == "ESTABLISH_SECURE:ACCEPTED" {
								// Establish secure channel
								result, err := crypto.EstablishSecureChannel(contact.PeerID, standardAddr)
								if err != nil {
									fmt.Printf("Error establishing secure channel: %v\n", err)
									fmt.Println("Falling back to regular connection")
									useSecure = false
								}
								if result["status"] == "established" {
									fmt.Println("Secure channel established successfully")
									time.Sleep(1 * time.Second)
									secureChannel = crypto.GetSecureChannel(contact.PeerID)
									if secureChannel == nil || !secureChannel.Established {
										fmt.Println("Failed to establish secure channel inner")
										fmt.Println("Falling back to regular connection")
										useSecure = false
									} else {
										fmt.Println("Secure channel established")
									}

								} else {
									fmt.Printf("Failed to establish secure channel: %s\n", result["message"])
								}

							} else {
								fmt.Println("Peer rejected secure channel request")
								fmt.Println("Falling back to regular connection")
								useSecure = false
							}
						}
					}
					sock.Close()
				}
			}
		} else {
			fmt.Println("Peer not authenticated, secure transfer not available")
			useSecure = false
		}
	}

	// Use secure channel if available
	if useSecure && secureChannel != nil && secureChannel.Established {
		requestFileSecure(secureChannel, filename)
	} else {

		requestFileRegular(host, port, filename)
	}
}

func requestFileRegular(host string, port int, filename string) {
	fmt.Printf("Requesting file '%s' from %s:%d\n", filename, host, port)

	// Create a new, dedicated connection for file transfer
	conn, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		fmt.Printf("Failed to connect for file transfer: %v\n", err)
		fmt.Printf("Attempting to find alternative sources...\n")

		fileHash := ""
		if hashManager != nil {
			hashInfo, exists := hashManager.GetFileHash(filename)
			if exists {
				fileHash = hashInfo.Hash
				fmt.Printf("Using hash %s for verification\n", fileHash)
			}
		}
		success, alternativePeer, err := network.RequestFileFromAlternative(
			filename,
			"",
			authentication.PeerID,
			fileHash,
		)

		if err != nil {
			fmt.Printf("Error finding alternative source: %v\n", err)
			return
		}

		if success {
			fmt.Printf("Successfully retrieved file from alternative peer: %s\n", alternativePeer)
			return
		}

		fmt.Printf("Failed to find alternative source for file\n")
		return

	}
	defer conn.Close()

	// Check if peer requires authentication
	if contactManager != nil {
		standardAddr := fmt.Sprintf("%s:12345", host)
		if !crypto.CheckPeerAuthenticated(standardAddr) {
			fmt.Println("Peer not authenticated, authenticating first...")
			success, err := crypto.InitiateAuthentication(fmt.Sprintf("%s:%d", host, port))
			if err != nil || !success {
				fmt.Printf("Authentication failed: %v\n", err)
				fmt.Println("Authentication required to download files")
				return
			}
			fmt.Println("Please try again after authentication is complete")
			return
		}
	}

	// Send file request message
	requestMsg := fmt.Sprintf("REQUEST_FILE:%s", filename)
	_, err = conn.Write([]byte(requestMsg))
	if err != nil {
		fmt.Printf("Failed to send file request: %v\n", err)
		return
	}

	// Create buffer reader for more reliable parsing
	reader := bufio.NewReader(conn)

	// Read initial response
	headerLine, err := reader.ReadString(':')
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return
	}

	// Check for error response
	if strings.HasPrefix(headerLine, "ERR") {
		fmt.Printf("Error from peer: %s\n", headerLine)
		return
	}

	// Parse file header (expected format: "FILE_DATA:filename:filesize:filehash:")
	if !strings.HasPrefix(headerLine, "FILE_DATA:") {
		fmt.Printf("Unexpected response: %s\n", headerLine)
		return
	}

	// Read filename
	filenamePart, err := reader.ReadString(':')
	if err != nil {
		fmt.Printf("Error reading filename: %v\n", err)
		return
	}
	transferFilename := filenamePart[:len(filenamePart)-1] // Remove trailing colon

	// Read filesize
	filesizePart, err := reader.ReadString(':')
	if err != nil {
		fmt.Printf("Error reading filesize: %v\n", err)
		return
	}
	filesizeStr := filesizePart[:len(filesizePart)-1] // Remove trailing colon
	filesize, err := strconv.Atoi(filesizeStr)
	if err != nil {
		fmt.Printf("Invalid file size: %s\n", filesizeStr)
		return
	}

	// Read hash if present
	fileHash := ""
	hashPart, err := reader.ReadString(':')
	if err == nil {
		fileHash = hashPart[:len(hashPart)-1] // Remove trailing colon
	}

	fmt.Printf("Receiving file: %s (%d bytes)\n", transferFilename, filesize)

	// Create directory for downloads if it doesn't exist
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Error getting home directory: %v\n", err)
		return
	}

	downloadDir := filepath.Join(homeDir, ".p2p-share", "shared")
	err = os.MkdirAll(downloadDir, 0755)
	if err != nil {
		fmt.Printf("Error creating download directory: %v\n", err)
		return
	}

	// Create file to save the downloaded content
	savePath := filepath.Join(downloadDir, transferFilename)
	file, err := os.Create(savePath)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer file.Close()

	// Read the file data
	bytesReceived := 0
	buffer := make([]byte, 4096)

	for bytesReceived < filesize {
		n, err := conn.Read(buffer)
		if err != nil && err != io.EOF {
			fmt.Printf("Error receiving file data: %v\n", err)
			return
		}

		if n == 0 {
			break // End of file
		}

		// Write data to file
		bytesToWrite := n
		if bytesReceived+n > filesize {
			bytesToWrite = filesize - bytesReceived
		}

		_, err = file.Write(buffer[:bytesToWrite])
		if err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
			return
		}

		bytesReceived += bytesToWrite

		// Display progress
		percentComplete := float64(bytesReceived) / float64(filesize) * 100
		if bytesReceived%40960 == 0 || bytesReceived == filesize { // Log every ~40KB or at completion
			fmt.Printf("Receiving: %.1f%%\n", percentComplete)
		}

		if bytesReceived >= filesize {
			break
		}
	}

	if bytesReceived < filesize {
		fmt.Printf("Warning: Received only %d of %d bytes\n", bytesReceived, filesize)
	}

	// Verify file hash if available
	if hashManager != nil && fileHash != "" {
		fmt.Println("Verifying file integrity...")
		verified, err := hashManager.VerifyFileHash(savePath, fileHash)
		if err != nil || !verified {
			fmt.Printf(" File verification failed: %v\n", err)

			// Ask if user wants to keep the file
			fmt.Print("Keep potentially corrupted file? (y/n): ")
			var keepFile string
			fmt.Scanln(&keepFile)
			if strings.ToLower(keepFile) != "y" {
				os.Remove(savePath)
				fmt.Println("File deleted")
				return
			}
			fmt.Println("File kept despite verification failure")
		} else {
			fmt.Println(" File integrity verified successfully")

			// Store hash information
			hashManager.AddFileHash(transferFilename, savePath, fmt.Sprintf("%s:%d", host, port))
		}
	}

	// Add to shared files list
	absPath, _ := filepath.Abs(savePath)
	if !contains(sharedFiles, absPath) {
		sharedFiles = append(sharedFiles, absPath)
	}

	// NEW CODE: Automatically encrypt the file after download for secure storage
	if secureStorage != nil {
		fmt.Println("Encrypting file for secure storage...")

		// Generate a random storage key
		storageKey, err := crypto.GenerateRandomKey(32)
		if err != nil {
			fmt.Printf("Error generating storage key: %v\n", err)
			return
		}

		// Store the key for future use
		keyPath := savePath + ".key"
		err = ioutil.WriteFile(keyPath, storageKey, 0600)
		if err != nil {
			fmt.Printf("Error saving encryption key: %v\n", err)
			return
		}

		// Encrypt the file
		outputPath, err := secureStorage.SecureStoreFile(savePath, string(storageKey))
		if err != nil {
			fmt.Printf("Error encrypting file for storage: %v\n", err)
			return
		}

		fmt.Printf("File encrypted and stored securely at: %s\n", outputPath)

		// Remove the unencrypted file
		err = os.Remove(savePath)
		if err != nil {
			fmt.Printf("Error removing unencrypted file: %v\n", err)
		} else {
			fmt.Println("Removed unencrypted version")
		}
	}
}

func requestFileSecure(channel *crypto.SecureChannel, filename string) {
	fmt.Printf("Requesting file '%s' securely\n", filename)

	// Send the request
	err := channel.SendEncrypted("REQUEST_FILE", filename)
	if err != nil {
		fmt.Printf("Error sending file request: %v\n", err)
		// Additional error handling or fallback to regular transfer
		return
	}

	fmt.Println("Secure file request sent")
	fmt.Println("The file will be transferred in the background")
	fmt.Println("You will be notified when the transfer is complete")
}

func processPendingVerifications() {
	pendingVerifications := crypto.GetPendingVerifications()
	if len(pendingVerifications) == 0 {
		return
	}

	fmt.Println("\nPending authentication requests:")
	var peerIDs []string
	i := 1
	for peerID, data := range pendingVerifications {
		peerIDs = append(peerIDs, peerID)
		fmt.Printf("%d. Peer %s - %s\n", i, peerID, data.ContactData.Address)
		i++
	}

	fmt.Print("\nEnter request number to process (or 0 to skip): ")
	var choice int
	fmt.Scanln(&choice)

	if choice == 0 {
		return
	}

	if choice < 1 || choice > len(peerIDs) {
		fmt.Println("Invalid choice")
		return
	}

	selectedPeerID := peerIDs[choice-1]
	fmt.Printf("Verify peer %s? (y/n): ", selectedPeerID)
	var confirm string
	fmt.Scanln(&confirm)

	crypto.ProcessVerificationResponse(selectedPeerID, strings.ToLower(confirm) == "y")
}

func setupSignalHandling() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nReceived termination signal")
		gracefulShutdown()
		os.Exit(0)
	}()
}

func gracefulShutdown() {
	fmt.Println("Closing all peer connections...")
	for addr, conn := range connectedPeers {
		fmt.Printf("Closing connection to %s\n", addr)
		conn.Close()
	}
	fmt.Println("Shutdown complete")
}
func handleSecureStorage(scanner *bufio.Scanner) {
	if secureStorage == nil {
		fmt.Println("Secure storage is not available")
		return
	}

	fmt.Println("\nSecure Storage Options:")
	fmt.Println("1. Store a file securely")
	fmt.Println("2. Retrieve a secure file")
	fmt.Println("3. List secure files")
	fmt.Println("4. Delete a secure file")
	fmt.Println("5. Return to main menu")

	fmt.Print("\nEnter option: ")
	scanner.Scan()
	choice := scanner.Text()

	switch choice {
	case "1":
		// Store a file securely
		fmt.Print("Enter file path to store securely: ")
		scanner.Scan()
		filePath := scanner.Text()

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			fmt.Println("File not found")
			return
		}

		fmt.Print("Enter passphrase (leave empty to auto-generate): ")
		scanner.Scan()
		passphrase := scanner.Text()

		outputPath, err := secureStorage.SecureStoreFile(filePath, passphrase)
		if err != nil {
			fmt.Printf("Error storing file securely: %v\n", err)
		} else {
			fmt.Printf("File stored securely at: %s\n", outputPath)
		}

	case "2":
		// Retrieve a secure file
		secureFiles, err := secureStorage.ListSecureFiles()
		if err != nil {
			fmt.Printf("Error listing secure files: %v\n", err)
			return
		}

		if len(secureFiles) == 0 {
			fmt.Println("No secure files found")
			return
		}

		fmt.Println("\nSecure files:")
		for i, file := range secureFiles {
			fmt.Printf("%d. %s\n", i+1, filepath.Base(file))
		}

		fmt.Print("\nEnter file number to retrieve: ")
		scanner.Scan()
		fileIdx, err := strconv.Atoi(scanner.Text())
		if err != nil || fileIdx < 1 || fileIdx > len(secureFiles) {
			fmt.Println("Invalid file selection")
			return
		}

		selectedFile := secureFiles[fileIdx-1]

		fmt.Print("Enter output path (leave empty for default): ")
		scanner.Scan()
		outputPath := scanner.Text()

		if outputPath == "" {
			// Use default output location in shared directory
			homeDir, err := os.UserHomeDir()
			if err != nil {
				fmt.Printf("Error getting home directory: %v\n", err)
				return
			}

			// Create shared directory if it doesn't exist
			sharedDir := filepath.Join(homeDir, ".p2p-share", "shared")
			err = os.MkdirAll(sharedDir, 0755)
			if err != nil {
				fmt.Printf("Error creating shared directory: %v\n", err)
				return
			}

			// Remove .enc extension and unique ID from filename
			baseName := filepath.Base(selectedFile)
			parts := strings.Split(strings.TrimSuffix(baseName, ".enc"), "_")
			if len(parts) > 1 {
				// Keep the original filename without the unique ID
				outputPath = filepath.Join(sharedDir, parts[0]+filepath.Ext(selectedFile))
			} else {
				outputPath = filepath.Join(sharedDir, baseName)
			}
		}

		fmt.Print("Enter passphrase (leave empty to use stored key): ")
		scanner.Scan()
		passphrase := scanner.Text()

		err = secureStorage.SecureRetrieveFile(selectedFile, outputPath, passphrase)
		if err != nil {
			fmt.Printf("Error retrieving secure file: %v\n", err)
		} else {
			fmt.Printf("File retrieved successfully to: %s\n", outputPath)
		}

	case "3":
		// List secure files
		secureFiles, err := secureStorage.ListSecureFiles()
		if err != nil {
			fmt.Printf("Error listing secure files: %v\n", err)
			return
		}

		if len(secureFiles) == 0 {
			fmt.Println("No secure files found")
			return
		}

		fmt.Println("\nSecure files:")
		for i, file := range secureFiles {
			fmt.Printf("%d. %s\n", i+1, filepath.Base(file))
		}

	case "4":
		// Delete a secure file
		secureFiles, err := secureStorage.ListSecureFiles()
		if err != nil {
			fmt.Printf("Error listing secure files: %v\n", err)
			return
		}

		if len(secureFiles) == 0 {
			fmt.Println("No secure files found")
			return
		}

		fmt.Println("\nSecure files:")
		for i, file := range secureFiles {
			fmt.Printf("%d. %s\n", i+1, filepath.Base(file))
		}

		fmt.Print("\nEnter file number to delete: ")
		scanner.Scan()
		fileIdx, err := strconv.Atoi(scanner.Text())
		if err != nil || fileIdx < 1 || fileIdx > len(secureFiles) {
			fmt.Println("Invalid file selection")
			return
		}

		selectedFile := secureFiles[fileIdx-1]

		fmt.Print("Are you sure you want to delete this file? (y/n): ")
		scanner.Scan()
		confirmation := scanner.Text()

		if strings.ToLower(confirmation) == "y" {
			err = secureStorage.DeleteSecureFile(selectedFile)
			if err != nil {
				fmt.Printf("Error deleting secure file: %v\n", err)
			} else {
				fmt.Println("File deleted successfully")
			}
		}

	case "5":
		return

	default:
		fmt.Println("Invalid option")
	}
}

// Add this new function to handle key migration
func handleKeyMigration(scanner *bufio.Scanner) {
	if contactManager == nil || authentication == nil {
		fmt.Println("Authentication system not initialized")
		return
	}

	fmt.Println("\nKey Migration Options:")
	fmt.Println("1. Initiate key migration")
	fmt.Println("2. Return to main menu")

	fmt.Print("\nEnter option: ")
	scanner.Scan()
	choice := scanner.Text()

	if choice != "1" {
		return
	}

	fmt.Println("\nInitiating key migration process...")
	fmt.Println("This will generate a new key pair and notify all your contacts")
	fmt.Print("Are you sure you want to continue? (y/n): ")
	scanner.Scan()
	confirmation := scanner.Text()

	if strings.ToLower(confirmation) != "y" {
		fmt.Println("Key migration cancelled")
		return
	}

	// Start key migration
	migration, err := crypto.InitiateMigration(authentication.PeerID, contactManager)
	if err != nil {
		fmt.Printf("Error initiating key migration: %v\n", err)
		return
	}

	// Notify contacts about the migration
	fmt.Println("Notifying trusted contacts about key migration...")
	err = migration.NotifyContacts()
	if err != nil {
		fmt.Printf("Error notifying contacts: %v\n", err)
		fmt.Print("Do you want to continue with the migration anyway? (y/n): ")
		scanner.Scan()
		confirmation := scanner.Text()
		if strings.ToLower(confirmation) != "y" {
			fmt.Println("Key migration cancelled")
			return
		}
	}

	// Complete the migration
	err = migration.CompleteMigration()
	if err != nil {
		fmt.Printf("Error completing key migration: %v\n", err)
		return
	}

	fmt.Println("✅ Key migration completed successfully")
	fmt.Println("You need to restart the application for the changes to take effect")
}

// Helper function to find a file in shared locations
func findSharedFile(filename string) string {
	// Check if file exists as an exact path
	if _, err := os.Stat(filename); err == nil {
		return filename
	}

	// Check if file exists in shared files by basename
	basename := filepath.Base(filename)
	for _, path := range sharedFiles {
		if filepath.Base(path) == basename {
			return path
		}
	}

	// Check in default shared directory
	homeDir, err := os.UserHomeDir()
	if err == nil {
		sharedPath := filepath.Join(homeDir, ".p2p-share", "shared", basename)
		if _, err := os.Stat(sharedPath); err == nil {
			return sharedPath
		}
	}

	return ""
}

// Helper function to get the file list as a string
func getFileListString() string {
	// Collect filenames from all shared files
	var fileList []string

	// Add explicitly shared files
	for _, path := range sharedFiles {
		fileList = append(fileList, filepath.Base(path))
	}

	// Check for files in the shared directory
	homeDir, err := os.UserHomeDir()
	if err == nil {
		sharedDir := filepath.Join(homeDir, ".p2p-share", "shared")
		files, err := os.ReadDir(sharedDir)
		if err == nil {
			for _, file := range files {
				if !file.IsDir() {
					fileList = append(fileList, file.Name())
				}
			}
		}
	}

	// Generate response string based on hash availability
	if hashManager != nil {
		// Get hash information for the files
		return hashManager.GetFileHashesAsString(fileList)
	} else {
		// No hashes available, use comma-separated list
		return strings.Join(fileList, ",")
	}
}
