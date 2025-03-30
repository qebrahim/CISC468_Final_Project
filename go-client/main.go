package main

import (
	"fmt"
	"log"
	"time"

	"p2p-file-sharing/go-client/internal/discovery" // Import your discovery package
)

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
	}

	time.Sleep(5 * time.Second) // Ensure results are printed before exit
}
