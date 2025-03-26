class Peer:
    def __init__(self, peer_id, address):
        self.peer_id = peer_id
        self.address = address
        self.connected_peers = {}

    def connect(self, peer):
        if peer.peer_id not in self.connected_peers:
            self.connected_peers[peer.peer_id] = peer
            print(f"Connected to peer: {peer.peer_id} at {peer.address}")

    def disconnect(self, peer):
        if peer.peer_id in self.connected_peers:
            del self.connected_peers[peer.peer_id]
            print(f"Disconnected from peer: {peer.peer_id}")

    def send_file_request(self, peer_id, file_name):
        if peer_id in self.connected_peers:
            print(f"Requesting file '{file_name}' from peer: {peer_id}")
            # Logic to send file request goes here

    def receive_file_request(self, peer_id, file_name):
        print(f"Received file request for '{file_name}' from peer: {peer_id}")
        # Logic to handle file request goes here

    def list_connected_peers(self):
        return list(self.connected_peers.keys())