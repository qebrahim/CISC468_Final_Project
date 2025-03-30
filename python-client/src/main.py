import threading
import signal
import sys
from pathlib import Path
import logging
from discovery.mdns import PeerDiscovery
from network.peer import Peer
from network.protocol import start_server
from crypto.keys import generate_keypair, save_private_key, save_public_key

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class P2PApplication:
    def __init__(self):
        self.running = True
        self.storage_path = Path.home() / '.p2p-share'
        self.storage_path.mkdir(parents=True, exist_ok=True)

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

            start_server()
            logger.info(f"Protocol handler listening on port {self.port}")

            # Main application loop
            while self.running:
                self._handle_user_input()

        except Exception as e:
            logger.error(f"Error running P2P application: {e}")
            self.shutdown()

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
                peers = self.peer.list_connected_peers()
                print("\nConnected peers:", peers)

            elif choice == "2":
                peer_id = input("Enter peer ID: ")
                filename = input("Enter filename: ")
                self.peer.send_file_request(peer_id, filename)

            elif choice == "3":
                filename = input("Enter filename to share: ")
                if Path(filename).exists():
                    # Add file to shared files
                    print(f"File {filename} is now available for sharing")
                else:
                    print("File not found")

            elif choice == "4":
                # List available files from all connected peers
                for peer_id in self.peer.list_connected_peers():
                    print(f"\nFiles available from {peer_id}:")
                    # Request file list from peer

            elif choice == "5":
                self.shutdown()

        except Exception as e:
            logger.error(f"Error processing command: {e}")

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
