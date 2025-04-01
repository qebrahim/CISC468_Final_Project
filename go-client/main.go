package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
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

	// Set up signal handling for graceful shutdown
	setupSignalHandling()

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
	fmt.Println("5. Exit")
}

func listConnectedPeers() {
	fmt.Println("\nConnected peers:")
	if len(connectedPeers) == 0 {
		fmt.Println("No peers connected")
		return
	}

	i := 1
	for peer := range connectedPeers {
		fmt.Printf("%d. %s\n", i, peer)
		i++
	}
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
		fmt.Printf("%d. %s\n", i, peer)
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

	// Request the file from the peer
	requestFileFromPeer(host, port, filename)
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

	// Check if the list is in the new format with hashes or old format
	if strings.Contains(fileList, ";") {
		// New format with hash information
		fileEntries := strings.Split(fileList, ";")

		if len(fileEntries) == 0 || (len(fileEntries) == 1 && fileEntries[0] == "") {
			fmt.Println("  No files available")
			return
		}

		for i, entry := range fileEntries {
			if entry == "" {
				continue
			}

			// Parse file,hash,size triplet
			fileParts := strings.Split(entry, ",")
			filename := fileParts[0]
			hash := ""
			size := ""

			if len(fileParts) >= 2 {
				hash = fileParts[1]
			}

			if len(fileParts) >= 3 {
				size = fileParts[2]
			}

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
			if hashManager != nil && hash != "" {
				sizeInt, _ := strconv.ParseInt(size, 10, 64)

				hashManager.Hashes[filename] = crypto.FileHashInfo{
					Hash:         hash,
					Size:         sizeInt,
					OriginPeer:   peerAddr,
					LastVerified: float64(time.Now().Unix()),
				}
			}
		}

		// Save updated hashes
		if hashManager != nil {
			hashManager.SaveHashes()
		}
	} else {
		// Old format (comma-separated filenames only)
		files := strings.Split(fileList, ",")

		if len(files) == 0 || (len(files) == 1 && files[0] == "") {
			fmt.Println("  No files available")
			return
		}

		for i, file := range files {
			if file != "" {
				fmt.Printf("  %d. %s\n", i+1, file)
			}
		}
	}
}

func receiveFileList(conn net.Conn, peerAddr string) {
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Printf("Error reading file list from %s: %v\n", peerAddr, err)
		return
	}

	response := string(buffer[:n])

	// Check for error response
	if strings.HasPrefix(response, "ERR") {
		errParts := strings.SplitN(response, ":", 2)
		if len(errParts) > 1 {
			fmt.Printf("Error from %s: %s\n", peerAddr, errParts[1])
		} else {
			fmt.Printf("Unknown error from %s\n", peerAddr)
		}
		return
	}

	// Process file list response (expected format: "FILE_LIST:file1,hash1,size1;file2,hash2,size2;...")
	if !strings.HasPrefix(response, "FILE_LIST:") {
		fmt.Printf("Unexpected response from %s: %s\n", peerAddr, response)
		return
	}

	// Extract file list
	parts := strings.SplitN(response, ":", 2)
	if len(parts) < 2 {
		fmt.Printf("Invalid file list response from %s\n", peerAddr)
		return
	}

	fileList := parts[1]

	// Handle empty file list
	if fileList == "" {
		fmt.Printf("\nFiles available from %s:\n", peerAddr)
		fmt.Println("  No files available")
		return
	}

	// Check if the response is in the new format with hashes or old format
	var files []string
	var filesWithHash []struct {
		Filename string
		Hash     string
		Size     string
	}

	// Check if we have semicolons (new format) or commas (old format)
	if strings.Contains(fileList, ";") {
		// New format with hash information
		fileEntries := strings.Split(fileList, ";")

		for _, entry := range fileEntries {
			if entry == "" {
				continue
			}

			// Parse file,hash,size triplet
			fileParts := strings.Split(entry, ",")
			fileInfo := struct {
				Filename string
				Hash     string
				Size     string
			}{
				Filename: fileParts[0],
				Hash:     "",
				Size:     "",
			}

			if len(fileParts) >= 2 {
				fileInfo.Hash = fileParts[1]
			}

			if len(fileParts) >= 3 {
				fileInfo.Size = fileParts[2]
			}

			filesWithHash = append(filesWithHash, fileInfo)
		}

		// Store hash information if hash manager is available
		if hashManager != nil {
			for _, fileInfo := range filesWithHash {
				if fileInfo.Filename != "" && fileInfo.Hash != "" {
					sizeInt, _ := strconv.ParseInt(fileInfo.Size, 10, 64)

					// Store hash information in our hash manager
					hashManager.Hashes[fileInfo.Filename] = crypto.FileHashInfo{
						Hash:         fileInfo.Hash,
						Size:         sizeInt,
						OriginPeer:   peerAddr,
						LastVerified: float64(time.Now().Unix()),
					}
				}
			}
			// Save updated hashes
			hashManager.SaveHashes()
		}
	} else {
		// Old format (comma-separated filenames only)
		if fileList != "" { // Handle empty list
			files = strings.Split(fileList, ",")
		} else {
			files = []string{}
		}
	}

	// Display the file list
	fmt.Printf("\nFiles available from %s:\n", peerAddr)

	if len(filesWithHash) > 0 {
		// Display new format with hash information
		if len(filesWithHash) == 0 || (len(filesWithHash) == 1 && filesWithHash[0].Filename == "") {
			fmt.Println("  No files available")
		} else {
			for i, fileInfo := range filesWithHash {
				sizeStr := ""
				if fileInfo.Size != "" {
					sizeInt, _ := strconv.ParseInt(fileInfo.Size, 10, 64)
					sizeStr = fmt.Sprintf(" (%d bytes)", sizeInt)
				}

				verifiedStr := ""
				if fileInfo.Hash != "" {
					verifiedStr = " [verifiable]"
				}

				fmt.Printf("  %d. %s%s%s\n", i+1, fileInfo.Filename, sizeStr, verifiedStr)
			}
		}
	} else {
		// Display old format
		if len(files) == 0 || (len(files) == 1 && files[0] == "") {
			fmt.Println("  No files available")
		} else {
			for i, file := range files {
				if file != "" {
					fmt.Printf("  %d. %s\n", i+1, file)
				}
			}
		}
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
		if len(parts) > 0 {
			command := parts[0]

			switch command {
			case "REQUEST_FILE":
				if len(parts) < 2 {
					conn.Write([]byte("ERR:INVALID_REQUEST"))
					continue
				}
				filename := parts[1]
				handleFileRequest(conn, filename)

			case "FILE_DATA":
				// Handle incoming file data (processed in requestFileFromPeer)

			case "FILE_LIST":
				// This is a response to our LIST_FILES request, not a command
				// It should be handled by receiveFileList, not here
				// This entry is just to prevent "Unknown command" messages

			case "LIST_FILES":
				handleFileListRequest(conn)

			case "ERR":
				errorMsg := "Unknown error"
				if len(parts) > 1 {
					errorMsg = parts[1]
				}
				fmt.Printf("Error from peer: %s\n", errorMsg)

			default:
				fmt.Printf("Unknown command: %s\n", command)
			}
		} else {
			fmt.Println("Received empty message")
		}
	}
}

func handleFileListRequest(conn net.Conn) {
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

	// Get hash information for files
	var response string
	if hashManager != nil {
		// Get hash information for the files
		hashInfo := hashManager.GetFileHashesAsString(fileList)
		response = fmt.Sprintf("FILE_LIST:%s", hashInfo)
	} else {
		// Fallback to old format without hashes
		response = fmt.Sprintf("FILE_LIST:%s", strings.Join(fileList, ","))
	}

	// Send the file list
	_, err = conn.Write([]byte(response))
	if err != nil {
		fmt.Printf("Error sending file list: %v\n", err)
	}
}

func requestFileFromPeer(host string, port int, filename string) {
	// Create a new, dedicated connection for file transfer
	newConn, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		fmt.Printf("Failed to connect for file transfer: %v\n", err)
		return
	}
	defer newConn.Close()

	// Check if we have hash information for this file
	var expectedHash string
	if hashManager != nil {
		if hashInfo, exists := hashManager.GetFileHash(filename); exists {
			expectedHash = hashInfo.Hash
			fmt.Printf("Found hash information for %s, will verify integrity\n", filename)
		}
	}

	// Send file request message
	requestMsg := fmt.Sprintf("REQUEST_FILE:%s", filename)
	_, err = newConn.Write([]byte(requestMsg))
	if err != nil {
		fmt.Printf("Failed to send file request: %v\n", err)
		return
	}

	fmt.Printf("File request for '%s' sent to %s:%d\n", filename, host, port)

	// Create a directory for downloads if it doesn't exist
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

	// For better debug information
	fmt.Println("Reading response...")

	// Use a buffered reader for more reliable protocol parsing
	reader := bufio.NewReader(newConn)

	// Read the first line which should contain the header
	headerLine, err := reader.ReadString(':')
	if err != nil {
		fmt.Printf("Error reading header: %v\n", err)
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

	// Continue reading header parts
	filenamePart, err := reader.ReadString(':')
	if err != nil {
		fmt.Printf("Error reading filename: %v\n", err)
		return
	}
	transferFilename := filenamePart[:len(filenamePart)-1] // Remove trailing colon

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
	hashPart, err := reader.ReadString(':')
	if err != nil {
		fmt.Printf("Error reading hash: %v\n", err)
		return
	}
	receivedHash := hashPart[:len(hashPart)-1] // Remove trailing colon

	fmt.Printf("Header parsed successfully: filename=%s, size=%d, hash=%s\n",
		transferFilename, filesize, receivedHash)

	// If we have a hash from before and it doesn't match the received hash, warn the user
	if expectedHash != "" && receivedHash != "" && expectedHash != receivedHash {
		fmt.Printf("⚠️ Warning: Received file hash differs from expected hash!\n")
		fmt.Printf("   Expected: %s\n", expectedHash)
		fmt.Printf("   Received: %s\n", receivedHash)

		fmt.Print("Continue with download? (y/n): ")
		var decision string
		fmt.Scanln(&decision)
		if strings.ToLower(decision) != "y" {
			fmt.Println("Download canceled")
			return
		}
	}

	fmt.Printf("Receiving file: %s (%d bytes)\n", transferFilename, filesize)

	// Create file to save the downloaded content
	savePath := filepath.Join(downloadDir, transferFilename)
	file, err := os.Create(savePath)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer file.Close()

	// Read the file data directly into the file
	bytesReceived := 0
	buffer := make([]byte, 4096)

	for bytesReceived < filesize {
		n, err := newConn.Read(buffer)
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
	if hashManager != nil && (receivedHash != "" || expectedHash != "") {
		hashToVerify := receivedHash
		if expectedHash != "" {
			// Prefer our existing hash if available
			hashToVerify = expectedHash
		}

		fmt.Println("Verifying file integrity...")
		verified, err := hashManager.VerifyFileHash(savePath, hashToVerify)
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

			// Store hash information for potential alternate source lookups
			if expectedHash == "" && receivedHash != "" {
				sourceAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
				_, err := hashManager.AddFileHash(transferFilename, savePath, sourceAddr)
				if err != nil {
					fmt.Printf("Warning: Failed to store file hash: %v\n", err)
				} else {
					fmt.Printf("Hash for %s saved successfully\n", transferFilename)
				}
			}
		}
	}

	fmt.Printf("File downloaded successfully to %s\n", savePath)

	// Update the list of shared files
	sharedFiles = append(sharedFiles, savePath)
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

func handleFileRequest(conn net.Conn, filename string) {
	// Check if file exists in shared files
	found := false
	var filePath string

	// First try to find in explicitly shared files
	for _, path := range sharedFiles {
		if filepath.Base(path) == filename {
			found = true
			filePath = path
			break
		}
	}

	// If not found in shared files, check if it exists in the current directory as fallback
	if !found {
		currentDirFile := filepath.Join(".", filename)
		if _, err := os.Stat(currentDirFile); err == nil {
			found = true
			filePath = currentDirFile
		}
	}

	// If still not found, check in the shared directory
	if !found {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			sharedDirFile := filepath.Join(homeDir, ".p2p-share", "shared", filename)
			if _, err := os.Stat(sharedDirFile); err == nil {
				found = true
				filePath = sharedDirFile
			}
		}
	}

	if !found {
		conn.Write([]byte("ERR:FILE_NOT_FOUND"))
		return
	}

	// Ask for user consent
	fmt.Printf("\nAllow peer to download %s? (y/n): ", filename)
	var consent string
	fmt.Scanln(&consent)

	if strings.ToLower(consent) != "y" {
		conn.Write([]byte("ERR:REQUEST_DENIED"))
		fmt.Println("File request denied")
		return
	}

	// Get or compute the file hash if hash manager is available
	var fileHash string
	if hashManager != nil {
		hashInfo, exists := hashManager.GetFileHash(filename)
		if exists {
			fileHash = hashInfo.Hash
		} else {
			// Calculate and store the hash
			var err error
			fileHash, err = hashManager.AddFileHash(filename, filePath, "")
			if err != nil {
				fmt.Printf("Warning: Failed to calculate file hash: %v\n", err)
				// Continue without hash if calculation fails
			}
		}
	}

	// Open and read the file
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

	fmt.Printf("File %s sent successfully\n", filename)
}
