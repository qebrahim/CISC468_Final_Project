package discovery

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

type MDNSDiscovery struct {
	serviceName string
	resolver    *zeroconf.Resolver
	server      *zeroconf.Server
	mutex       sync.Mutex
	isRunning   bool
}

func NewMDNSDiscovery(serviceName string) *MDNSDiscovery {
	resolver, err := zeroconf.NewResolver(nil) // Ensure it listens on all interfaces
	if err != nil {
		log.Fatalf("❌ Failed to create resolver: %v", err)
	}

	return &MDNSDiscovery{
		serviceName: serviceName,
		resolver:    resolver,
	}
}

// StartAdvertising begins advertising this peer's service
func (d *MDNSDiscovery) StartAdvertising(peerID string, port int) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.isRunning {
		return nil // Already advertising
	}

	fmt.Println("📢 Starting mDNS advertisement...")

	var err error
	// Register service for discovery
	d.server, err = zeroconf.Register(
		fmt.Sprintf("go-peer-%s", peerID), // Instance name (must be unique)
		d.serviceName,                     // Service type
		"local.",                          // Domain
		port,                              // Port
		[]string{"txtv=1", fmt.Sprintf("id=%s", peerID)}, // TXT records
		nil, // Interface to advertise on (nil = all)
	)

	if err != nil {
		return fmt.Errorf("❌ Failed to register mDNS service: %v", err)
	}

	d.isRunning = true
	fmt.Println("✅ mDNS advertisement started successfully")
	return nil
}

// StopAdvertising stops the advertisement service
func (d *MDNSDiscovery) StopAdvertising() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.server != nil {
		fmt.Println("🛑 Stopping mDNS advertisement...")
		d.server.Shutdown()
		d.server = nil
		d.isRunning = false
	}
}

func (d *MDNSDiscovery) DiscoverPeers() ([]string, error) {
	entries := make(chan *zeroconf.ServiceEntry)

	// Create a longer timeout context for the overall operation
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Create a done channel to signal when we want to stop early
	done := make(chan struct{})

	// Track when we found our first peer
	firstPeerFound := false
	var firstPeerTime time.Time

	fmt.Println("🔍 Starting mDNS discovery...")
	err := d.resolver.Browse(ctx, d.serviceName, "local.", entries)
	if err != nil {
		return nil, fmt.Errorf("❌ Failed to browse: %v", err)
	}

	// Collect results
	var peers []string

	// Start a goroutine to close the done channel after short timeout from first peer
	go func() {
		for {
			// If we found at least one peer, wait 2 seconds for more peers then exit
			if firstPeerFound && time.Since(firstPeerTime) > 2*time.Second {
				close(done)
				return
			}

			// Check every 100ms
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
	}()

	// Process discovered peers
	for {
		select {
		case entry, ok := <-entries:
			if !ok {
				fmt.Println("🔴 Channel closed")
				return peers, nil
			}

			fmt.Println("✅ Found service:", entry.Service)
			fmt.Println("   ➡ Hostname:", entry.HostName)
			fmt.Println("   ➡ IPv4:", entry.AddrIPv4)
			fmt.Println("   ➡ IPv6:", entry.AddrIPv6)
			fmt.Println("   ➡ Port:", entry.Port)
			fmt.Println("   ➡ TXT Records:", entry.Text)

			if len(entry.AddrIPv4) > 0 {
				peers = append(peers, fmt.Sprintf("%s:%d", entry.AddrIPv4[0].String(), entry.Port))

				// Mark when we found the first peer
				if !firstPeerFound {
					firstPeerFound = true
					firstPeerTime = time.Now()
					fmt.Println("🕒 Found first peer, will continue searching briefly...")
				}
			}

		case <-done:
			fmt.Println("✓ Found peers, stopping discovery early")
			return peers, nil

		case <-ctx.Done():
			fmt.Println("⏳ Discovery timed out")
			return peers, nil
		}
	}
}
