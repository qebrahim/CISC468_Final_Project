import os
import json
import base64
import socket
import logging
import time
import shutil
from pathlib import Path
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils

from crypto.keys import generate_keypair, save_private_key, save_public_key, load_private_key, load_public_key

logger = logging.getLogger(__name__)


class KeyMigration:
    """Handles the process of migrating to a new cryptographic key."""

    def __init__(self, peer_id, contact_manager, authentication):
        """Initialize with peer ID and managers for contacts and authentication."""
        self.peer_id = peer_id
        self.contact_manager = contact_manager
        self.authentication = authentication
        self.storage_path = Path.home() / '.p2p-share' / 'keys'

    def initiate_migration(self):
        """
        Start the key migration process.

        Returns:
            dict: Information about the migration status
        """
        try:
            # Create backup directory
            backup_dir = self.storage_path / 'backup' / \
                datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_dir.mkdir(parents=True, exist_ok=True)

            # Backup current keys
            private_key_path = self.storage_path / 'private.pem'
            public_key_path = self.storage_path / 'public.pem'

            if private_key_path.exists() and public_key_path.exists():
                # Backup the keys
                shutil.copy2(private_key_path, backup_dir / 'private.pem')
                shutil.copy2(public_key_path, backup_dir / 'public.pem')

                # Store old keys
                self.old_private_key = load_private_key(private_key_path)
                self.old_public_key = load_public_key(public_key_path)

                # Generate new key pair
                self.new_private_key, self.new_public_key = generate_keypair()

                # Store the new public key in PEM format for sharing
                self.new_public_key_pem = self.new_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')

                return {
                    "status": "ready",
                    "message": "Key migration initiated. Ready to notify contacts."
                }
            else:
                return {
                    "status": "error",
                    "message": "Current keys not found. Cannot initiate migration."
                }

        except Exception as e:
            logger.error(f"Error initiating key migration: {e}")
            return {
                "status": "error",
                "message": f"Error initiating key migration: {e}"
            }

    def notify_contacts(self):
        """
        Notify all trusted contacts about the key migration.

        Returns:
            dict: Information about the notification status
        """
        try:
            # Get all trusted contacts
            contacts = self.contact_manager.get_all_trusted_contacts()

            if not contacts:
                return {
                    "status": "warning",
                    "message": "No trusted contacts to notify."
                }

            # Create migration message
            migration_time = time.time()
            message = f"KEY_MIGRATION:{self.peer_id}:{migration_time}"

            # Sign the message with the old private key
            signature = self._sign_message(message)

            # Create notification object
            notification = {
                "peer_id": self.peer_id,
                "old_public_key": self.authentication.get_public_key_pem(),
                "new_public_key": self.new_public_key_pem,
                "signature": signature,
                "migration_time": migration_time
            }

            # Convert to JSON
            notification_json = json.dumps(notification)

            # Send notification to all contacts
            success_count = 0
            failure_count = 0

            print(f"Notifying {len(contacts)} contacts about key migration...")

            for peer_id, contact in contacts.items():
                try:
                    # Extract host and port
                    addr = contact.get("address", "")
                    if not addr or ":" not in addr:
                        logger.warning(
                            f"Invalid address for contact {peer_id}")
                        failure_count += 1
                        continue

                    host, port_str = addr.split(":")
                    port = int(port_str)

                    # Connect to the peer
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)  # 5 second timeout
                    sock.connect((host, port))

                    # Send notification
                    sock.sendall(
                        f"MIGRATE_KEY:{notification_json}".encode('utf-8'))

                    # Wait for acknowledgment (with timeout)
                    sock.settimeout(10)  # 10 second timeout for response
                    try:
                        response = sock.recv(4096).decode('utf-8')
                        if response.startswith("MIGRATE_KEY_ACK:"):
                            ack_data = json.loads(response.split(":", 1)[1])
                            status = ack_data.get("status")

                            if status == "accepted":
                                print(
                                    f"Contact {peer_id} accepted key migration")
                                success_count += 1
                            else:
                                print(
                                    f"Contact {peer_id} rejected key migration: {status}")
                                failure_count += 1
                        else:
                            print(
                                f"Unexpected response from {peer_id}: {response[:20]}")
                            failure_count += 1
                    except socket.timeout:
                        print(f"No response from {peer_id} (timeout)")
                        failure_count += 1

                    sock.close()

                except Exception as e:
                    logger.error(f"Error notifying contact {peer_id}: {e}")
                    failure_count += 1

            return {
                "status": "complete",
                "message": f"Notification complete. Success: {success_count}, Failures: {failure_count}",
                "success_count": success_count,
                "failure_count": failure_count
            }

        except Exception as e:
            logger.error(f"Error notifying contacts: {e}")
            return {
                "status": "error",
                "message": f"Error notifying contacts: {e}"
            }

    def complete_migration(self):
        """
        Complete the key migration by saving the new keys.

        Returns:
            dict: Information about the completion status
        """
        try:
            # Save the new keys
            private_key_path = self.storage_path / 'private.pem'
            public_key_path = self.storage_path / 'public.pem'

            save_private_key(self.new_private_key, private_key_path)
            save_public_key(self.new_public_key, public_key_path)

            print("✅ New keys saved successfully")

            # Reload the keys in the authentication system
            self.authentication.load_keys()

            return {
                "status": "complete",
                "message": "Key migration completed successfully."
            }

        except Exception as e:
            logger.error(f"Error completing key migration: {e}")
            return {
                "status": "error",
                "message": f"Error completing key migration: {e}"
            }

    def _sign_message(self, message):
        """Sign a message with the old private key."""
        if not hasattr(self, 'old_private_key'):
            raise ValueError("Old private key not available")

        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message = message.encode('utf-8')

        # Create signature
        signature = self.old_private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Return base64 encoded signature
        return base64.b64encode(signature).decode('utf-8')


def handle_key_migration(message, addr, conn, contact_manager, authentication):
    """
    Handle a key migration message from a peer.

    Args:
        message: The migration message
        addr: The peer's address
        conn: The connection socket
        contact_manager: The contact manager
        authentication: The authentication system

    Returns:
        bool: True if the migration was handled successfully
    """
    try:
        # Parse the migration notification
        notification = json.loads(message)

        peer_id = notification.get("peer_id")
        old_public_key = notification.get("old_public_key")
        new_public_key = notification.get("new_public_key")
        signature = notification.get("signature")
        migration_time = notification.get("migration_time")

        # Add more detailed logging for debugging
        message_text = f"KEY_MIGRATION:{peer_id}:{migration_time}"
        print(f"DEBUG PYTHON - Message to verify: {message_text}")
        print(
            f"DEBUG PYTHON - Message bytes (hex): {message_text.encode('utf-8').hex()}")
        print(f"DEBUG PYTHON - Base64 signature: {signature}")
        print(
            f"DEBUG PYTHON - Raw signature (hex): {base64.b64decode(signature).hex()}")
        print(
            f"DEBUG PYTHON - Public key first 50 chars: {old_public_key[:50]}...")

        if not peer_id or not old_public_key or not new_public_key or not signature or not migration_time:
            logger.error("Invalid key migration notification")
            send_migration_ack(conn, authentication.peer_id, "invalid_format")
            return False

        print(f"\nReceived key migration notification from peer {peer_id}")

        # Check if this is a trusted contact
        contact = contact_manager.get_trusted_contact(peer_id)
        if not contact:
            logger.error(f"Received key migration from unknown peer {peer_id}")
            send_migration_ack(conn, authentication.peer_id, "untrusted_peer")
            return False

        # Verify the old public key matches our stored public key
        if contact.get("public_key") != old_public_key:
            logger.error(
                f"Old public key doesn't match stored key for peer {peer_id}")
            send_migration_ack(conn, authentication.peer_id, "key_mismatch")
            return False

        # Verify signature
        message_text = f"KEY_MIGRATION:{peer_id}:{migration_time}"
        if not verify_migration_signature(message_text, signature, old_public_key):
            logger.error(
                f"Invalid signature in key migration from peer {peer_id}")
            send_migration_ack(conn, authentication.peer_id,
                               "invalid_signature")
            return False

        # Notify the user and get consent
        print(f"Peer {peer_id} is migrating to a new key.")
        print("Do you want to accept this key migration? (y/n): ", end="", flush=True)

        consent = input().lower().strip()

        if consent != 'y':
            print(f"Rejected key migration from peer {peer_id}")
            send_migration_ack(conn, authentication.peer_id, "rejected")
            return False

        # Update the contact with the new public key
        contact["public_key"] = new_public_key
        contact["verified_at"] = migration_time
        contact["last_seen"] = time.time()
        contact_manager.save_contacts()

        print(f"Updated public key for peer {peer_id}")

        # Send acknowledgment
        send_migration_ack(conn, authentication.peer_id, "accepted")

        return True

    except Exception as e:
        logger.error(f"Error handling key migration: {e}")
        try:
            send_migration_ack(
                conn, authentication.peer_id if authentication else "unknown", "error")
        except:
            pass
        return False


def verify_migration_signature(message, signature_b64, public_key_pem):
    try:
        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message

        print(f"DEBUG PYTHON - Raw message bytes (hex): {message_bytes.hex()}")

        # Calculate the hash like Go does
        message_hash = hashlib.sha256(message_bytes).digest()
        print(f"DEBUG PYTHON - Message hash (hex): {message_hash.hex()}")

        # Decode the signature
        signature = base64.b64decode(signature_b64)
        print(f"DEBUG PYTHON - Signature length: {len(signature)}")

        # Load the public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )

        # Try both methods to verify
        try:
            # Method 1: Original method (expecting the verify function to hash)
            print("DEBUG PYTHON - Trying verification method 1 (internal hashing)")
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("DEBUG PYTHON - Method 1 succeeded!")
            return True
        except Exception as e1:
            print(f"DEBUG PYTHON - Method 1 failed: {e1}")

            try:
                # Method 2: Pre-hashed method (matching Go's approach)
                print("DEBUG PYTHON - Trying verification method 2 (pre-hashed)")
                public_key.verify(
                    signature,
                    message_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    utils.Prehashed(hashes.SHA256())
                )
                print("DEBUG PYTHON - Method 2 succeeded!")
                return True
            except Exception as e2:
                print(f"DEBUG PYTHON - Method 2 failed: {e2}")
                raise e2

    except InvalidSignature:
        logger.warning("Invalid signature in migration verification")
        return False
    except Exception as e:
        logger.error(f"Error verifying migration signature: {e}")
        return False


def send_migration_ack(conn, peer_id, status):
    """
    Send an acknowledgment for a key migration notification.

    Args:
        conn: The connection socket
        peer_id: Our peer ID
        status: The acknowledgment status
    """
    try:
        ack = {
            "peer_id": peer_id,
            "status": status
        }

        ack_json = json.dumps(ack)
        conn.sendall(f"MIGRATE_KEY_ACK:{ack_json}".encode('utf-8'))
    except Exception as e:
        logger.error(f"Error sending migration acknowledgment: {e}")
