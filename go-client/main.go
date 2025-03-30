package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"p2p-file-sharing/go-client/internal/discovery" // Import your discovery package
)

func connectToPeer(address string, port int) {
	// Create full address with port
	fullAddress := net.JoinHostPort(address, fmt.Sprintf("%d", port))
	fmt.Printf("🔌 Attempting to connect to %s\n", fullAddress)

	// Establish TCP connection
	conn, err := net.Dial("tcp", fullAddress)
	if err != nil {
		fmt.Printf("❌ Connection failed: %v\n", err)
		return
	}
	defer conn.Close()

	fmt.Println("✅ Connection established!")

	// Send a test message
	message := "Hello from Go client!"
	_, err = conn.Write([]byte(message))
	if err != nil {
		fmt.Printf("❌ Failed to send message: %v\n", err)
		return
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Printf("❌ Failed to read response: %v\n", err)
		return
	}

	fmt.Printf("📩 Received: %s\n", buffer[:n])
}

func main() {
	serviceName := "_p2p-share._tcp." // Define your service name

	// Create a new MDNSDiscovery instance
	mdns := discovery.NewMDNSDiscovery(serviceName)

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

	time.Sleep(5 * time.Second) // Ensure results are printed before exit
}
