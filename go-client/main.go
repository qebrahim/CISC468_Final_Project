package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"p2p-file-sharing/go-client/internal/discovery"
	"p2p-file-sharing/go-client/internal/network/peer"
)

var (
	mainPeer *peer.Peer
	running  = true
)

func connectToPeer(address string, port int) {
	// Create full address with port
	fullAddress := net.JoinHostPort(address, fmt.Sprintf("%d", port))
	fmt.Printf("🔌 Attempting to connect to %s\n", fullAddress)

	// Use the secure peer connection
	err := mainPeer.Connect(fullAddress)
	if err != nil {
		fmt.Printf("❌ Connection failed: %v\n", err)
		return
	}

	fmt.Println("✅ Connection established securely!")
}

func handleUserInput() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n📋 P2P File Sharing Menu:")
	fmt.Println("1. List connected peers")
	fmt.Println("2. Request file")
	fmt.Println("3. Share file")
	fmt.Println("4. Migrate keys (for security)")
	fmt.Println("5. Exit")

	fmt.Print("\nEnter your choice (1-5): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		peerList := mainPeer.ListConnectedPeers()
		if len(peerList) == 0 {
			fmt.Println("No peers connected.")
		} else {
			fmt.Println("\n🔗 Connected peers:")
			for i, peerID := range peerList {
				fmt.Printf("%d. %s\n", i+1, peerID)
			}
		}
	case "2":
		peerList := mainPeer.ListConnectedPeers()
		if len(peerList) == 0 {
			fmt.Println("No peers connected.")
			return
		}

		fmt.Println("\n🔗 Connected peers:")
		for i, peerID := range peerList {
			fmt.Printf("%d. %s\n", i+1, peerID)
		}

		fmt.Print("\nEnter peer number: ")
		peerNumStr, _ := reader.ReadString('\n')
		peerNumStr = strings.TrimSpace(peerNumStr)

		peerNum := 0
		fmt.Sscanf(peerNumStr, "%d", &peerNum)

		if peerNum < 1 || peerNum > len(peerList) {
			fmt.Println("❌ Invalid peer number.")
			return
		}

		selectedPeerID := peerList[peerNum-1]

		fmt.Print("Enter filename to request: ")
		fileName, _ := reader.ReadString('\n')
		fileName = strings.TrimSpace(fileName)

		if fileName == "" {
			fmt.Println("❌ Filename cannot be empty.")
			return
		}

		fmt.Printf("📥 Requesting file '%s' from peer %s...\n", fileName, selectedPeerID)
		err := mainPeer.RequestFile(selectedPeerID, fileName)
		if err != nil {
			fmt.Printf("❌ File request failed: %v\n", err)
		}
	case "3":
		fmt.Print("Enter path to file you want to share: ")
		filePath, _ := reader.ReadString('\n')
		filePath = strings.TrimSpace(filePath)

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			fmt.Println("❌ File not found!")
			return
		}

		// Copy file to shared directory
		fileName := filepath.Base(filePath)
		destPath := filepath.Join(mainPeer.SharedDir, fileName)

		srcFile, err := os.Open(filePath)
		if err != nil {
			fmt.Printf("❌ Error opening file: %v\n", err)
			return
		}
		defer srcFile.Close()

		destFile, err := os.Create(destPath)
		if err != nil {
			fmt.Printf("❌ Error creating destination file: %v\n", err)
			return
		}
		defer destFile.Close()

		_, err = destFile.ReadFrom(srcFile)
		if err != nil {
			fmt.Printf("❌ Error copying file: %v\n", err)
			return
		}

		fmt.Printf("✅ File '%s' is now available for sharing!\n", fileName)
	case "4":
		fmt.Println("🔄 Initiating key migration for security...")
		err := mainPeer.MigrateKeys()
		if err != nil {
			fmt.Printf("❌ Key migration failed: %v\n", err)
		} else {
			fmt.Println("✅ Keys successfully migrated! New keys are now in use.")
		}
	case "5":
		fmt.Println("👋 Exiting application...")
		running = false
	default:
		fmt.Println("❌ Invalid choice. Please try again.")
	}
}

func handleIncomingConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	fmt.Printf("📥 New connection from: %s\n", remoteAddr)

	// Read request type
	requestType := make([]byte, 12)
	_, err := conn.Read(requestType)
	if err != nil {
		fmt.Printf("⚠️ Error reading request type: %v\n", err)
		return
	}

	// Handle different request types
	switch string(requestType) {
	case "FILE_REQUEST":
		// Send acknowledgment
		conn.Write([]byte("ACK"))

		// Read encrypted request
		buffer := make([]byte, 4096)
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Printf("⚠️ Error reading file request: %v\n", err)
			return
		}

		// For simplicity, we'll assume the requester ID is already known
		// In a real implementation, this would come from the authentication process
		requesterID := "unknown"

		// Handle file request
		err = mainPeer.HandleFileRequest(conn, buffer[:n], requesterID)
		if err != nil {
			fmt.Printf("⚠️ Error handling file request: %v\n", err)
		}
	default:
		fmt.Printf("⚠️ Unknown request type: %s\n", string(requestType))
	}
}

func main() {
	// Generate peer ID
	peerID := fmt.Sprintf("go-%d", time.Now().UnixNano()%10000)
	fmt.Printf("🚀 Starting P2P File Sharing Client (ID: %s)\n", peerID)

	// Setup directories
	homePath, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("❌ Failed to get home directory: %v", err)
	}

	storagePath := filepath.Join(homePath, ".p2p-share-go")
	keysDir := filepath.Join(storagePath, "keys")
	sharedDir := filepath.Join(storagePath, "shared")

	// Create directories
	os.MkdirAll(keysDir, 0700)
	os.MkdirAll(sharedDir, 0755)

	// Get local IP
	host := getLocalIP()
	port := 12345

	// Initialize peer
	mainPeer, err = peer.NewPeer(peerID, fmt.Sprintf("%s:%d", host, port), keysDir, sharedDir)
	if err != nil {
		log.Fatalf("❌ Failed to create peer: %v", err)
	}

	// Set up graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n🛑 Received shutdown signal. Closing application...")
		running = false
	}()

	serviceName := "_p2p-share._tcp."

	// Create a new MDNSDiscovery instance
	mdns := discovery.NewMDNSDiscovery(serviceName)

	// Start advertising our presence
	go func() {
		fmt.Println("📢 Starting service advertisement...")
		err := mdns.StartAdvertising(peerID, port)
		if err != nil {
			fmt.Printf("⚠️ Warning: Failed to advertise service: %v\n", err)
		}
	}()

	// First, discover peers
	fmt.Println("🔍 Browsing for services...")
	peers, err := mdns.DiscoverPeers()
	if err != nil {
		log.Fatalf("❌ Error discovering peers: %v", err)
	}

	// Print discovered peers
	if len(peers) == 0 {
		fmt.Println("⚠️ No peers found.")
	} else {
		fmt.Println("✅ Discovered peers:")
		for _, peer := range peers {
			fmt.Println("   ➡", peer)
		}

		// Connect to the first discovered peer
		if len(peers) > 0 {
			parts := strings.Split(peers[0], ":")
			host := parts[0]
			port := 12345 // Use the port from your Python server
			connectToPeer(host, port)
		}
	}

	// Start listener for incoming connections
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("❌ Failed to start listener: %v", err)
	}
	defer listener.Close()

	fmt.Println("👂 Listening for incoming connections...")

	// Start connection acceptor in a goroutine
	go func() {
		for running {
			conn, err := listener.Accept()
			if err != nil {
				if !running {
					return // Application is shutting down
				}
				fmt.Printf("⚠️ Error accepting connection: %v\n", err)
				continue
			}

			// Handle connection in a new goroutine
			go handleIncomingConnection(conn)
		}
	}()

	// Main application loop
	for running {
		// Wait a bit then prompt for user input
		time.Sleep(2 * time.Second)
		handleUserInput()
	}

	// Cleanup before exit
	mdns.StopAdvertising()
	fmt.Println("👋 Application closed.")
}

// getLocalIP returns the non-loopback local IP of the host
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "localhost"
	}

	for _, address := range addrs {
		// Check the address type and if it is not a loopback
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "localhost"
}
