import socket
import json
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
            try:
                peer = self.connected_peers[peer_id]
                response = peer.receive_file_request(self.peer_id, file_name)
                
                if response and isinstance(response, dict):
                    if response['status'] == 'approved':
                        # Create socket connection to peer
                        host, port = peer.address.split(':')
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.connect((host, int(port)))
                            
                            # Send file request
                            request = {
                                'type': 'file_request',
                                'file_name': file_name,
                                'requester': self.peer_id
                            }
                            s.sendall(json.dumps(request).encode())
                            
                            # Receive file data
                            file_path = self.shared_directory / file_name
                            with open(file_path, 'wb') as f:
                                while True:
                                    data = s.recv(1024)
                                    if not data:
                                        break
                                    f.write(data)
                            
                            # Verify file hash
                            if self._verify_file_hash(file_path, response['file_hash']):
                                print(f"File '{file_name}' successfully received and verified")
                                return True
                            else:
                                print("File verification failed")
                                file_path.unlink()  # Delete corrupted file
                                return False
                else:
                    print("File request denied or invalid response")
                    return False
                    
            except Exception as e:
                print(f"Error requesting file: {e}")
                return False

    def receive_file_request(self, peer_id, file_name):
        print(f"Received file request for '{file_name}' from peer: {peer_id}")
        try:
            file_path = self.shared_directory / file_name
            if file_path.exists():
                # Calculate file hash
                file_hash = self._calculate_file_hash(file_path)
                
                # Request user consent
                consent = input(f"Allow {peer_id} to download {file_name}? (y/n): ")
                if consent.lower() == 'y':
                    return {
                        'status': 'approved',
                        'file_hash': file_hash,
                        'file_size': file_path.stat().st_size
                    }
                else:
                    return {'status': 'denied'}
            else:
                return {'status': 'not_found'}
                
        except Exception as e:
            print(f"Error handling file request: {e}")
            return {'status': 'error', 'message': str(e)}

    def list_connected_peers(self):
        return list(self.connected_peers.keys())