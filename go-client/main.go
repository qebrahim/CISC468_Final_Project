package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"p2p-file-sharing/go-client/internal/discovery"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Global variables to store state
var connectedPeers map[string]net.Conn
var sharedFiles []string

func main() {
	// Initialize
	connectedPeers = make(map[string]net.Conn)
	serviceName := "_p2p-share._tcp."
	mdns := discovery.NewMDNSDiscovery(serviceName)

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
	fmt.Printf("File %s is now available for sharing\n", filename)
}

func listAvailableFiles() {
	if len(connectedPeers) == 0 {
		fmt.Println("No peers connected")
		return
	}

	fmt.Println("\nRequesting file lists from connected peers...")

	for peerAddr, conn := range connectedPeers {
		fmt.Printf("Requesting files from %s...\n", peerAddr)

		// Send file list request message with a colon as delimiter to match Python server expectations
		_, err := conn.Write([]byte("LIST_FILES:"))
		if err != nil {
			fmt.Printf("Error requesting file list from %s: %v\n", peerAddr, err)
			continue
		}

		// Process the response in a separate goroutine to avoid blocking
		go receiveFileList(conn, peerAddr)
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

	// Process file list response (expected format: "FILE_LIST:file1,file2,file3")
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
	files := strings.Split(fileList, ",")

	// Display the file list
	fmt.Printf("\nFiles available from %s:\n", peerAddr)
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
	var fileNames []string

	// Add explicitly shared files
	for _, path := range sharedFiles {
		fileNames = append(fileNames, filepath.Base(path))
	}

	// Check for files in the shared directory
	homeDir, err := os.UserHomeDir()
	if err == nil {
		sharedDir := filepath.Join(homeDir, ".p2p-share", "shared")
		files, err := os.ReadDir(sharedDir)
		if err == nil {
			for _, file := range files {
				if !file.IsDir() {
					fileNames = append(fileNames, file.Name())
				}
			}
		}
	}

	// Build the response
	fileList := strings.Join(fileNames, ",")
	response := fmt.Sprintf("FILE_LIST:%s", fileList)

	// Send the file list
	_, err = conn.Write([]byte(response))
	if err != nil {
		fmt.Printf("Error sending file list: %v\n", err)
	}
}

func requestFileFromPeer(host string, port int, filename string) {
	fullAddress := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, exists := connectedPeers[fullAddress]

	if !exists {
		fmt.Printf("Not connected to %s, attempting to connect...\n", fullAddress)
		connectToPeer(host, port)
		conn, exists = connectedPeers[fullAddress]
		if !exists {
			fmt.Println("Failed to connect to peer")
			return
		}
	}

	// Send file request message (compatible with Python server)
	requestMsg := fmt.Sprintf("REQUEST_FILE:%s", filename)
	_, err := conn.Write([]byte(requestMsg))
	if err != nil {
		fmt.Printf("Failed to send file request: %v\n", err)
		return
	}

	fmt.Printf("File request for '%s' sent to %s\n", filename, fullAddress)

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

	// Receive the file data (now compatible with Python server)
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return
	}

	response := string(buffer[:n])

	// Check for error response
	if strings.HasPrefix(response, "ERR") {
		errParts := strings.SplitN(response, ":", 2)
		if len(errParts) > 1 {
			fmt.Printf("Error from peer: %s\n", errParts[1])
		} else {
			fmt.Println("File not found or request denied")
		}
		return
	}

	// Parse file header (expected format: "FILE_DATA:filename:filesize:")
	if !strings.HasPrefix(response, "FILE_DATA:") {
		fmt.Printf("Unexpected response: %s\n", response)
		return
	}

	// Extract filename and filesize from header
	headerParts := strings.SplitN(response, ":", 4)
	if len(headerParts) < 3 {
		fmt.Printf("Invalid file header: %s\n", response)
		return
	}

	transferFilename := headerParts[1]
	filesize, err := strconv.Atoi(headerParts[2])
	if err != nil {
		fmt.Printf("Invalid file size in header: %s\n", headerParts[2])
		return
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

	// Write any data already received after the header
	headerSize := len(headerParts[0]) + len(headerParts[1]) + len(headerParts[2]) + 3 // 3 for the colons
	if n > headerSize {
		_, err = file.Write(buffer[headerSize:n])
		if err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
			return
		}
		bytesReceived := n - headerSize

		// Continue receiving the file
		for bytesReceived < filesize {
			n, err = conn.Read(buffer)
			if err != nil {
				fmt.Printf("Error receiving file data: %v\n", err)
				return
			}

			_, err = file.Write(buffer[:n])
			if err != nil {
				fmt.Printf("Error writing to file: %v\n", err)
				return
			}

			bytesReceived += n

			// Display progress
			percentComplete := float64(bytesReceived) / float64(filesize) * 100
			if bytesReceived%40960 == 0 { // Log every ~40KB
				fmt.Printf("Receiving: %.1f%%\n", percentComplete)
			}
		}

		fmt.Printf("File downloaded successfully to %s\n", savePath)
	}
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
	// Send file header (compatible with Python client expectations)
	header := fmt.Sprintf("FILE_DATA:%s:%d:", filepath.Base(filePath), fileSize)
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
