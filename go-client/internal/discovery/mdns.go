package discovery

import (
    "fmt"
    "github.com/grandcat/zeroconf"
    "net"
    "time"
)

type MDNSDiscovery struct {
    serviceName string
    resolver    *zeroconf.Resolver
}

func NewMDNSDiscovery(serviceName string) *MDNSDiscovery {
    return &MDNSDiscovery{
        serviceName: serviceName,
        resolver:    zeroconf.NewResolver(net.DefaultResolver),
    }
}

func (d *MDNSDiscovery) DiscoverPeers() ([]string, error) {
    entries := make(chan *zeroconf.ServiceEntry)
    go func() {
        time.Sleep(time.Second * 5)
        close(entries)
    }()

    err := d.resolver.Browse("_yourservice._tcp", "local.", entries)
    if err != nil {
        return nil, fmt.Errorf("failed to browse: %v", err)
    }

    var peers []string
    for entry := range entries {
        peers = append(peers, entry.AddrIPv4[0].String())
    }

    return peers, nil
}