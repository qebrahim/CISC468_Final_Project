package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"p2p-file-sharing/go-client/internal/crypto"
	"p2p-file-sharing/go-client/internal/discovery"
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
}

var secureFileTransfers = make(map[string]*SecureFileTransfer)

func main() {
	// Initialize
	connectedPeers = make(map[string]net.Conn)
	serviceName := "_p2p-share._tcp."
	mdns := discovery.NewMDNSDiscovery(serviceName)

	// Generate a peer ID (first 8 chars of a UUID)
	peerID := generatePeerID()
	fmt.Printf("🔌 Running as peer ID: %s\n", peerID)

	// Initialize hash manager
	var err error
	hashManager, err = crypto.NewHashManager(peerID)
	if err != nil {
		fmt.Printf("⚠️ Warning: Failed to initialize hash manager: %v\n", err)
		// Continue without hash verification if failed
	} else {
		fmt.Println("✅ Hash manager initialized for file verification")
	}

	// Initialize security system
	setupSecurity(peerID)

	// Set up signal handling for graceful shutdown
	setupSignalHandling()

	// Start TCP server to listen for incoming connections
	startServer()

	// Discover initial peers
	fmt.Println("🔍 Browsing for services...")
	peers, err := mdns.DiscoverPeers()
	if err != nil {
		fmt.Printf("❌ Error discovering peers: %v\n", err)
	} else {
		if len(peers) == 0 {
			fmt.Println("⚠️ No peers found initially.")
		} else {
			fmt.Println("✅ Discovered peers:")
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
		fmt.Printf("⚠️ Warning: Failed to get home directory: %v\n", err)
		return
	}

	keysDir := filepath.Join(homeDir, ".p2p-share", "keys")
	err = os.MkdirAll(keysDir, 0755)
	if err != nil {
		fmt.Printf("⚠️ Warning: Failed to create keys directory: %v\n", err)
		return
	}

	privateKeyPath := filepath.Join(keysDir, "private.pem")
	publicKeyPath := filepath.Join(keysDir, "public.pem")

	// Check if key files exist, generate them if not
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		fmt.Println("Generating new key pair...")
		err = crypto.GenerateKeyPair(privateKeyPath, publicKeyPath)
		if err != nil {
			fmt.Printf("⚠️ Warning: Failed to generate key pair: %v\n", err)
			return
		}
		fmt.Println("✅ Key pair generated successfully")
	}

	// Initialize contact manager
	contactManager, err = crypto.NewContactManager(peerID)
	if err != nil {
		fmt.Printf("⚠️ Warning: Failed to initialize contact manager: %v\n", err)
		return
	}

	// Initialize authentication system
	authentication, err = crypto.NewPeerAuthentication(peerID, contactManager)
	if err != nil {
		fmt.Printf("⚠️ Warning: Failed to initialize authentication system: %v\n", err)
		return
	}

	// Initialize authentication protocol
	// Initialize authentication protocol
	crypto.InitAuthentication(peerID, contactManager, authentication)
	fmt.Println("✅ Security system initialized")
}

// startServer initializes a TCP server to handle incoming connections
func startServer() {
	// Start server on a separate goroutine
	go func() {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", serverPort))
		if err != nil {
			fmt.Printf("❌ Error starting server: %v\n", err)
			return
		}
		defer listener.Close()

		fmt.Printf("✅ Server listening on port %d\n", serverPort)
		// Add this to your main.go or where your application starts
		fmt.Printf("DEBUG: ContactManager initialized with storage path: %s\n", contactManager.StoragePath)

		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Printf("❌ Error accepting connection: %v\n", err)
				continue
			}

			remoteAddr := conn.RemoteAddr().String()
			fmt.Printf("✅ Accepted connection from %s\n", remoteAddr)

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
	fmt.Println("8. Exit")
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
		fmt.Printf("❌ Connection failed: %v\n", err)
		return
	}

	fmt.Println("✅ Connection established!")

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
		fmt.Printf("📩 Received from %s: %s\n", peerAddr, message)

		// Parse and process the message
		parts := strings.SplitN(message, ":", 2)
		if len(parts) < 2 {
			fmt.Printf("Invalid message format from %s\n", peerAddr)
			continue
		}

		command := parts[0]

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
		if command == "SECURE" {
			// Process secure channel message
			if len(parts) > 1 {
				_, err := crypto.HandleSecureMessage(conn, peerAddr, message)
				if err != nil {
					fmt.Printf("Error handling secure message: %v\n", err)
				}
			}
			continue
		}

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
	basename := filepath.Base(filename)
	for _, path := range sharedFiles {
		if filepath.Base(path) == basename {
			found = true
			filePath = path
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

	// Ask for user consent
	fmt.Printf("\nAllow %s to download %s? (y/n): ", displayPeer, filename)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	consent := scanner.Text()

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
		// Encrypt this chunk
		chunk := buffer[:bytesRead]
		encryptedChunk, err := crypto.Encrypt(chunk, transferKey)
		if err != nil {
			fmt.Printf("Error encrypting chunk: %v\n", err)
			channel.SendEncrypted("ERROR", fmt.Sprintf("ENCRYPTION_FAILED:%s", err.Error()))
			return
		}

		// Encode encrypted chunk as base64
		chunkB64 := base64.StdEncoding.EncodeToString(encryptedChunk)

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
	err = channel.SendEncrypted("FILE_END", filename)
	if err != nil {
		fmt.Printf("Error sending end of file marker: %v\n", err)
		return
	}

	fmt.Printf("File %s sent securely\n", filename)
}

// This function would be part of the secure channel message handling in main.go
func handleSecureFileTransfer(peerID string, messageType string, payload string) {
	// Access the global transfer state map
	if messageType == "FILE_CHUNK" {
		// Process a file chunk
		transfer, exists := secureFileTransfers[peerID]
		if !exists {
			fmt.Printf("No active file transfer for peer %s\n", peerID)
			return
		}

		// Decode the chunk
		encryptedChunkB64 := payload
		encryptedChunk, err := base64.StdEncoding.DecodeString(encryptedChunkB64)
		if err != nil {
			fmt.Printf("Error decoding file chunk: %v\n", err)
			return
		}
		var chunk []byte
		// Decrypt the chunk if we have an encryption key
		if transfer.TransferKey != nil {
			chunk, err := crypto.Decrypt(encryptedChunk, transfer.TransferKey)
			if err != nil {
				fmt.Printf("Error decrypting file chunk: %v\n", err)
				return
			}

			// Write decrypted chunk to file
			_, err = transfer.File.Write(chunk)
			if err != nil {
				fmt.Printf("Error writing file chunk: %v\n", err)
				return
			}
		} else {
			// No encryption key, write directly (backwards compatibility)
			_, err = transfer.File.Write(encryptedChunk)
			if err != nil {
				fmt.Printf("Error writing file chunk: %v\n", err)
				return
			}
		}

		transfer.Received += len(chunk)

		// Display progress
		percentComplete := float64(transfer.Received) / float64(transfer.Size) * 100
		if transfer.Received%40960 == 0 { // Log every ~40KB
			fmt.Printf("Receiving (secure): %.1f%%\n", percentComplete)
		}
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
								if err != nil || result["status"] != "initiated" {
									fmt.Printf("Error establishing secure channel: %v\n", err)
									fmt.Println("Falling back to regular connection")
									useSecure = false
								} else {
									// Wait for channel to be established
									time.Sleep(1 * time.Second)
									secureChannel = crypto.GetSecureChannel(contact.PeerID)
									if secureChannel == nil || !secureChannel.Established {
										fmt.Println("Failed to establish secure channel")
										fmt.Println("Falling back to regular connection")
										useSecure = false
									} else {
										fmt.Println("Secure channel established")
									}
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
			fmt.Printf("⚠️ File verification failed: %v\n", err)

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
			fmt.Println("✅ File integrity verified successfully")

			// Store hash information
			hashManager.AddFileHash(transferFilename, savePath, fmt.Sprintf("%s:%d", host, port))
		}
	}

	fmt.Printf("File downloaded successfully to %s\n", savePath)

	// Add to shared files list
	absPath, _ := filepath.Abs(savePath)
	if !contains(sharedFiles, absPath) {
		sharedFiles = append(sharedFiles, absPath)
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
