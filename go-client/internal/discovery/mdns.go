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
		log.Fatalf("❌ Failed to create resolver: %v", err)
	}

	return &MDNSDiscovery{
		serviceName: serviceName,
		resolver:    resolver,
	}
}

func (d *MDNSDiscovery) DiscoverPeers() ([]string, error) {
	entries := make(chan *zeroconf.ServiceEntry)

	// Set a timeout context for browsing
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fmt.Println("🔍 Starting mDNS discovery...")
	err := d.resolver.Browse(ctx, d.serviceName, "local.", entries)
	if err != nil {
		return nil, fmt.Errorf("❌ Failed to browse: %v", err)
	}

	// Collect results
	var peers []string
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
				peers = append(peers, entry.AddrIPv4[0].String())
			}
		case <-ctx.Done():
			fmt.Println("⏳ Discovery timed out.")
			return peers, nil
		}
	}
}
