import threading
import signal
import sys
from pathlib import Path
import logging
import time
from discovery.mdns import PeerDiscovery
from network.peer import Peer
from network.protocol import start_server, add_shared_file, request_file, init_hash_manager
from crypto.keys import generate_keypair, save_private_key, save_public_key

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class P2PApplication:
    def __init__(self):
        self.running = True
        self.storage_path = Path.home() / '.p2p-share'
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # Create shared directory
        self.shared_directory = self.storage_path / 'shared'
        self.shared_directory.mkdir(exist_ok=True)

        # Track connected peers
        self.connected_peers = set()
        self.connection_event = threading.Event()

        # Generate peer ID and keys
        self.peer_id = self._generate_peer_id()
        self._setup_keys()

        # Initialize components
        self.port = 12345
        self.peer = Peer(self.peer_id, f"localhost:{self.port}")
        self.discovery = PeerDiscovery(self.peer_id, self.port)

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def start(self):
        try:
            logger.info(f"Starting P2P application (Peer ID: {self.peer_id})")

            # Start discovery service
            self.discovery.start_advertising()
            logger.info("Peer discovery service started")

            # Start server with connection callback and peer_id for hash manager
            self.server_socket, self.server_thread = start_server(
                connection_callback=self._on_peer_connected,
                peer_id=self.peer_id  # Pass peer_id to initialize hash manager
            )
            logger.info(f"Protocol handler listening on port {self.port}")

            # Wait for initial connection before showing menu
            logger.info("Waiting for peer connections...")
            print("Waiting for connection from another peer...")

            # Main application loop
            while self.running:
                # Wait for at least one connection before showing menu
                if not self.connected_peers:
                    self.connection_event.wait(5)  # Check every 5 seconds
                    continue

                self._handle_user_input()

        except Exception as e:
            logger.error(f"Error running P2P application: {e}")
            self.shutdown()

    def _on_peer_connected(self, addr):
        """Callback method when a new peer connects"""
        peer_address = f"{addr[0]}:{addr[1]}"
        logger.info(f"New peer connected: {peer_address}")

        # Always use the standard port for communication, not the ephemeral port
        # This fixes the issue where we try to connect back to the wrong port
        standard_peer_address = f"{addr[0]}:12345"

        self.connected_peers.add(standard_peer_address)
        self.connection_event.set()  # Signal that we have a connection

    def _on_peer_disconnected(self, addr):
        """Callback method when a peer disconnects"""
        peer_address = f"{addr[0]}:{addr[1]}"
        if peer_address in self.connected_peers:
            self.connected_peers.remove(peer_address)
            logger.info(f"Peer disconnected: {peer_address}")

            # If no more peers, reset the event
            if not self.connected_peers:
                self.connection_event.clear()
                print("\nAll peers disconnected. Waiting for new connections...")

    def shutdown(self):
        logger.info("Shutting down P2P application...")
        self.running = False
        self.discovery.stop_advertising()
        sys.exit(0)

    def _handle_user_input(self):
        print("\nAvailable commands:")
        print("1. List connected peers")
        print("2. Request file")
        print("3. Share file")
        print("4. List available files")
        print("5. Exit")

        try:
            choice = input("\nEnter command number: ")

            if choice == "1":
                print("\nConnected peers:")
                for i, peer in enumerate(self.connected_peers):
                    print(f"{i+1}. {peer}")

            elif choice == "2":
                if not self.connected_peers:
                    print("No peers connected")
                    return

                # Let user select a peer from the list
                print("\nSelect a peer:")
                for i, peer in enumerate(self.connected_peers):
                    print(f"{i+1}. {peer}")

                peer_idx = int(input("Enter peer number: ")) - 1
                if 0 <= peer_idx < len(self.connected_peers):
                    peer_addr = list(self.connected_peers)[peer_idx]
                    filename = input("Enter filename: ")

                    # Extract host and port from peer_addr
                    host, port = peer_addr.split(':')

                    # Request the file
                    print(f"Requesting file '{filename}' from {peer_addr}...")
                    success = request_file(
                        host=host, port=int(port), filename=filename)

                    if success:
                        print(
                            f"File '{filename}' successfully downloaded to {self.shared_directory}")
                    else:
                        print(f"Failed to download file '{filename}'")
                else:
                    print("Invalid peer selection")

            elif choice == "3":
                filename = input("Enter filename to share: ")
                file_path = Path(filename)

                if file_path.exists():
                    # Add file to shared files list
                    if add_shared_file(str(file_path)):
                        print(f"File {filename} is now available for sharing")

                        # Also copy to shared directory for easy access
                        try:
                            target_path = self.shared_directory / file_path.name
                            with open(file_path, 'rb') as src, open(target_path, 'wb') as dst:
                                dst.write(src.read())
                            print(
                                f"File copied to shared directory: {target_path}")
                        except Exception as e:
                            logger.error(
                                f"Error copying file to shared directory: {e}")
                    else:
                        print(f"File {filename} is already being shared")
                else:
                    print("File not found")

            elif choice == "4":
                # List locally shared files
                print("\nLocally shared files:")
                local_files = list(self.shared_directory.glob('*'))
                if local_files:
                    for i, file_path in enumerate(local_files):
                        file_size = file_path.stat().st_size
                        print(f"{i+1}. {file_path.name} ({file_size} bytes)")
                else:
                    print("No files are currently being shared")

            elif choice == "5":
                self.shutdown()

        except Exception as e:
            logger.error(f"Error processing command: {e}")
            print(f"Error: {e}")

    def _generate_peer_id(self):
        import uuid
        return str(uuid.uuid4())[:8]

    def _setup_keys(self):
        keys_dir = self.storage_path / 'keys'
        keys_dir.mkdir(exist_ok=True)

        private_key_path = keys_dir / 'private.pem'
        public_key_path = keys_dir / 'public.pem'

        if not private_key_path.exists() or not public_key_path.exists():
            logger.info("Generating new key pair...")
            private_key, public_key = generate_keypair()
            save_private_key(private_key, private_key_path)
            save_public_key(public_key, public_key_path)
            logger.info("Key pair generated and saved")

    def _handle_shutdown(self, signum, frame):
        self.shutdown()


def main():
    app = P2PApplication()
    app.start()


if __name__ == "__main__":
    main()
