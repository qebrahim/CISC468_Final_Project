def test_peer_discovery():
    # Test case for successful peer discovery
    discovered_peers = discover_peers()
    assert len(discovered_peers) > 0, "No peers discovered"

    # Test case for peer discovery timeout
    with pytest.raises(DiscoveryTimeout):
        discover_peers(timeout=1)  # Assuming a timeout of 1 second

    # Test case for discovering a specific peer
    peer_address = "192.168.1.10"
    discovered_peers = discover_peers()
    assert peer_address in discovered_peers, f"Peer {peer_address} not found in discovered peers"

    # Test case for handling no available peers
    clear_peers()  # Assuming this function clears the peer list
    discovered_peers = discover_peers()
    assert len(discovered_peers) == 0, "Peers should be empty after clearing"