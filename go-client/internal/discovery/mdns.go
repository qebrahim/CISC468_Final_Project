package discovery

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/grandcat/zeroconf"
)

type MDNSDiscovery struct {
	serviceName string
	resolver    *zeroconf.Resolver
}

func NewMDNSDiscovery(serviceName string) *MDNSDiscovery {
	resolver, err := zeroconf.NewResolver(nil) // Ensure it listens on all interfaces
	if err != nil {
		log.Fatalf(" Failed to create resolver: %v", err)
	}

	return &MDNSDiscovery{
		serviceName: serviceName,
		resolver:    resolver,
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

	fmt.Println(" Starting mDNS discovery...")
	err := d.resolver.Browse(ctx, d.serviceName, "local.", entries)
	if err != nil {
		return nil, fmt.Errorf(" Failed to browse: %v", err)
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
				fmt.Println(" Channel closed")
				return peers, nil
			}

			fmt.Println(" Found service:", entry.Service)
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
					fmt.Println(" Found first peer, will continue searching briefly...")
				}
			}

		case <-done:
			fmt.Println("✓ Found peers, stopping discovery early")
			return peers, nil

		case <-ctx.Done():
			fmt.Println(" Discovery timed out")
			return peers, nil
		}
	}
}
