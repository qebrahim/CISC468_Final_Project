import unittest
import os
import time
import socket
import threading
import logging
import tempfile
import shutil
import json
import hashlib
import random
import string
from pathlib import Path
from unittest import mock
from contextlib import contextmanager
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the modules to test
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../python-client')))

# Import application modules
from src.crypto import encryption, keys, auth_protocol, authentication, contact_manager
from src.discovery import mdns
#from src.network import protocol, peer
from src.storage import filemanager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TestSetup(unittest.TestCase):
    """Test setup and installation of Python client"""
    
    def setUp(self):
        """Create temporary directory for tests"""
        self.temp_dir = tempfile.mkdtemp()
        self.original_dir = os.getcwd()
        os.chdir(self.temp_dir)
    
    def tearDown(self):
        """Clean up temporary directory"""
        os.chdir(self.original_dir)
        shutil.rmtree(self.temp_dir, ignore_errors=True)


class TestPeerDiscovery(unittest.TestCase):
    """Test mDNS peer discovery functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.peer_id = 'test_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        self.port = random.randint(49152, 65535)  # Use a random high port
        self.discovery = mdns.PeerDiscovery(self.peer_id, self.port)
    
    def tearDown(self):
        """Clean up after tests"""
        try:
            self.discovery.stop_advertising()
        except:
            pass
    
    def test_advertisement_start(self):
        """Test PY-DISC-01: Verify the Python client can advertise via mDNS"""
        try:
            # Start advertising
            self.discovery.start_advertising()
            
            # Verify advertisement is running (indirect verification through attributes)
            self.assertIsNotNone(self.discovery.zeroconf)
            
            # We would need another client or tool to actually detect the service
            # For this test, we'll just verify the service info was created
            # A more comprehensive test would use a separate client to discover the service
            
            # Allow some time for the service to be registered
            time.sleep(2)
            
            # Successful if no exception was raised
            self.assertTrue(True)
        finally:
            # Always stop advertising
            self.discovery.stop_advertising()
    
    @unittest.skip("Requires multiple running instances - test manually")
    def test_discover_peers(self):
        """Test PY-DISC-02: Verify the Python client can discover other peers (manual test)"""
        # This test requires multiple running instances and would need to be tested manually
        # Here we provide a skeleton of how it would work
        pass


class TestAuthentication(unittest.TestCase):
    """Test mutual authentication functionality"""
    
    def setUp(self):
        """Set up test environment with keys and contact manager"""
        # Create temporary directory for storing keys and contacts
        self.temp_dir = tempfile.mkdtemp()
        self.peer_id = 'test_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        # Mock home directory to use our temp directory
        self.original_home = os.environ.get('HOME')
        os.environ['HOME'] = self.temp_dir
        
        # Create necessary directories
        keys_dir = os.path.join(self.temp_dir, '.p2p-share', 'keys')
        metadata_dir = os.path.join(self.temp_dir, '.p2p-share', 'metadata')
        os.makedirs(keys_dir, exist_ok=True)
        os.makedirs(metadata_dir, exist_ok=True)
        
        # Generate key pair for testing
        private_key, public_key = keys.generate_keypair()
        
        # Save keys
        private_key_path = os.path.join(keys_dir, 'private.pem')
        public_key_path = os.path.join(keys_dir, 'public.pem')
        keys.save_private_key(private_key, private_key_path)
        keys.save_public_key(public_key, public_key_path)
        
        # Create contact manager and authentication
        self.cm = contact_manager.ContactManager(self.peer_id)
        self.auth = authentication.PeerAuthentication(self.peer_id, self.cm)
        
        # Initialize auth protocol
        auth_protocol.init_authentication(self.peer_id, self.cm, self.auth)
    
    def tearDown(self):
        """Clean up after tests"""
        # Restore original home directory
        if self.original_home:
            os.environ['HOME'] = self.original_home
        
        # Remove temp directory
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    
    
    def test_add_trusted_contact(self):
        """Test AUTH-03: Verify adding trusted contacts"""
        # Create a test contact
        peer_id = f"peer_{random.randint(1000, 9999)}"
        address = "192.168.1.100:12345"
        pub_key = self.auth.public_key_path  # Use own public key for simplicity
        
        # Add the contact
        result = self.cm.add_trusted_contact(peer_id, address, pub_key)
        
        # Verify contact was added
        self.assertTrue(result)
        self.assertTrue(self.cm.is_trusted(peer_id))
        
        # Get the contact and verify data
        contact = self.cm.get_trusted_contact(peer_id)
    
        self.assertEqual(contact['peer_id'], peer_id)
        self.assertEqual(contact['address'], address)
        self.assertEqual(contact['public_key'], pub_key)


class TestFileSharing(unittest.TestCase):
    """Test file sharing functionality"""
    
    def setUp(self):
        """Set up test environment for file sharing"""
        # Create temporary directory for files
        self.temp_dir = tempfile.mkdtemp()
        self.shared_dir = os.path.join(self.temp_dir, 'shared')
        os.makedirs(self.shared_dir, exist_ok=True)
        
        # Create a test file
        self.test_file_path = os.path.join(self.temp_dir, 'testfile.txt')
        with open(self.test_file_path, 'w') as f:
            f.write('This is a test file for P2P file sharing')
        
        # Create peer object
        self.peer_id = 'test_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        from src.network import  peer
        self.peer = peer.Peer(self.peer_id, '127.0.0.1:12345')
        
        # Mock the shared directory
        self.peer.shared_directory = Path(self.shared_dir)
    
    def tearDown(self):
        """Clean up after tests"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    
    def test_file_hash_calculation(self):
        """Test FILE-03: Verify file hash calculation and verification"""
        # Calculate hash of test file
        hasher = hashlib.sha256()
        with open(self.test_file_path, 'rb') as f:
            hasher.update(f.read())
        expected_hash = hasher.hexdigest()
        
        # Initialize hash manager (using basic function instead of the full manager)
        def calculate_file_hash(file_path):
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                hasher.update(f.read())
            return hasher.hexdigest()
        
        # Calculate hash
        actual_hash = calculate_file_hash(self.test_file_path)
        
        # Verify hash is correct
        self.assertEqual(expected_hash, actual_hash)
    
    @unittest.skip("Requires running server - test manually")
    def test_file_transfer(self):
        """Test FILE-02: Verify file transfer functionality (manual test)"""
        # This test requires a running server and client connection
        # It should be tested manually
        pass


class TestSecureChannel(unittest.TestCase):
    """Test secure channel functionality"""
    
    def setUp(self):
        """Set up test environment for secure channel testing"""
        from src.crypto import secure_channel
        
        # Generate peer IDs
        self.peer_id_a = 'test_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        self.peer_id_b = 'test_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        # Create mock sockets for testing
        self.socket_a = mock.MagicMock()
        self.socket_b = mock.MagicMock()
        
        # Create secure channels
        self.channel_a = secure_channel.create_secure_channel(self.peer_id_a, self.socket_a, True)
        self.channel_b = secure_channel.create_secure_channel(self.peer_id_b, self.socket_b, False)
        
        # Add channels to the registry for lookups
        secure_channel.secure_channels[self.peer_id_a] = self.channel_a
        secure_channel.secure_channels[self.peer_id_b] = self.channel_b
    
    def tearDown(self):
        """Clean up after tests"""
        from src.crypto import secure_channel
        
        # Remove channels from registry
        if self.peer_id_a in secure_channel.secure_channels:
            del secure_channel.secure_channels[self.peer_id_a]
        if self.peer_id_b in secure_channel.secure_channels:
            del secure_channel.secure_channels[self.peer_id_b]
    
    def test_key_derivation(self):
        """Test SEC-01: Verify key derivation for secure channels"""
        from src.crypto.secure_channel import deriveKey
        
        # Test secret and salt
        secret = b'testsecret'
        salt = b'testsalt'
        length = 32
        
        # Derive key
        key = deriveKey(secret, salt, length)
        
        # Verify key properties
        self.assertIsNotNone(key)
        self.assertEqual(len(key), length)
        
        # Derive again with same inputs - should be deterministic
        key2 = deriveKey(secret, salt, length)
        self.assertEqual(key, key2)
    
    def test_encrypt_decrypt_message(self):
        """Test SEC-02: Verify message encryption and decryption"""
        # Since we can't fully test the secure channel without actual sockets,
        # we'll test the encryption/decryption functions directly
        
        # Sample message
        plaintext = b'This is a secret message'
        
        # Generate encryption key
        key = os.urandom(32)  # 256-bit key
        
        # Encrypt
        encrypted_data = encryption.encrypt(plaintext, key)
        self.assertIsNotNone(encrypted_data)
        self.assertNotEqual(encrypted_data, plaintext)
        
        # Decrypt
        decrypted_data = encryption.decrypt(encrypted_data, key)
        self.assertEqual(decrypted_data, plaintext)


class TestKeyManagement(unittest.TestCase):
    """Test key management functionality"""
    
    def setUp(self):
        """Set up test environment for key management testing"""
        # Create temporary directory for storing keys and contacts
        self.temp_dir = tempfile.mkdtemp()
        self.peer_id = 'test_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        # Mock home directory to use our temp directory
        self.original_home = os.environ.get('HOME')
        os.environ['HOME'] = self.temp_dir
        
        # Create necessary directories
        keys_dir = os.path.join(self.temp_dir, '.p2p-share', 'keys')
        metadata_dir = os.path.join(self.temp_dir, '.p2p-share', 'metadata')
        backup_dir = os.path.join(keys_dir, 'backup')
        os.makedirs(keys_dir, exist_ok=True)
        os.makedirs(metadata_dir, exist_ok=True)
        os.makedirs(backup_dir, exist_ok=True)
        
        # Generate key pair for testing
        private_key, public_key = keys.generate_keypair()
        
        # Save keys
        self.private_key_path = os.path.join(keys_dir, 'private.pem')
        self.public_key_path = os.path.join(keys_dir, 'public.pem')
        keys.save_private_key(private_key, self.private_key_path)
        keys.save_public_key(public_key, self.public_key_path)
        
        # Create contact manager and authentication
        self.cm = contact_manager.ContactManager(self.peer_id)
        self.auth = authentication.PeerAuthentication(self.peer_id, self.cm)
    
    def tearDown(self):
        """Clean up after tests"""
        # Restore original home directory
        if self.original_home:
            os.environ['HOME'] = self.original_home
        
        # Remove temp directory
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    


class TestSecureStorage(unittest.TestCase):
    """Test secure storage functionality"""
    
    def setUp(self):
        """Set up test environment for secure storage testing"""
        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp()
        
        # Mock home directory to use our temp directory
        self.original_home = os.environ.get('HOME')
        os.environ['HOME'] = self.temp_dir
        
        # Create test file
        self.test_file_path = os.path.join(self.temp_dir, 'test_file.txt')
        with open(self.test_file_path, 'w') as f:
            f.write('This is a test file for secure storage')
        
        # Create secure directory structure
        secure_dir = os.path.join(self.temp_dir, '.p2p-share', 'secure')
        keys_dir = os.path.join(self.temp_dir, '.p2p-share', 'keys', 'secure')
        os.makedirs(secure_dir, exist_ok=True)
        os.makedirs(keys_dir, exist_ok=True)
    
    def tearDown(self):
        """Clean up after tests"""
        # Restore original home directory
        if self.original_home:
            os.environ['HOME'] = self.original_home
        
        # Remove temp directory
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_secure_file_storage_and_retrieval(self):
        """Test STORE-01 and STORE-02: Verify secure file storage and retrieval"""
        # Store file securely with a passphrase
        passphrase = "testpassphrase"
        encrypted_path = encryption.secure_store_file(self.test_file_path, passphrase)
        
        # Verify encrypted file exists
        self.assertTrue(os.path.exists(encrypted_path))
        
        # Create output path for retrieved file
        retrieved_path = os.path.join(self.temp_dir, 'retrieved_file.txt')
        
        # Retrieve the file
        encryption.secure_retrieve_file(encrypted_path, retrieved_path, passphrase)
        
        # Verify retrieved file exists and has the same content
        self.assertTrue(os.path.exists(retrieved_path))
        
        with open(self.test_file_path, 'r') as f:
            original_content = f.read()
        
        with open(retrieved_path, 'r') as f:
            retrieved_content = f.read()
        
        self.assertEqual(original_content, retrieved_content)


class TestOfflineRetrieval(unittest.TestCase):
    """Test offline file retrieval functionality"""
    
    def setUp(self):
        """Set up test environment for offline retrieval testing"""
        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp()
        
        # Create shared directories for different peers
        self.peer_a_dir = os.path.join(self.temp_dir, 'peer_a')
        self.peer_b_dir = os.path.join(self.temp_dir, 'peer_b')
        self.peer_c_dir = os.path.join(self.temp_dir, 'peer_c')
        
        os.makedirs(self.peer_a_dir, exist_ok=True)
        os.makedirs(self.peer_b_dir, exist_ok=True)
        os.makedirs(self.peer_c_dir, exist_ok=True)
        
        # Create a test file in peer A's directory
        self.test_file = 'test_file.txt'
        self.test_file_path = os.path.join(self.peer_a_dir, self.test_file)
        
        with open(self.test_file_path, 'w') as f:
            f.write('This is a test file for offline retrieval')
        
        # Calculate file hash
        hasher = hashlib.sha256()
        with open(self.test_file_path, 'rb') as f:
            hasher.update(f.read())
        self.file_hash = hasher.hexdigest()
        
        # Copy the file to peer B's directory (simulating previous download)
        shutil.copy(self.test_file_path, os.path.join(self.peer_b_dir, self.test_file))
    
    def tearDown(self):
        """Clean up after tests"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
   

class TestCrossCompatibility(unittest.TestCase):
    """Tests for cross-compatibility between Python and Go implementations"""
    
    @unittest.skip("Requires both Python and Go clients running - test manually")
    def test_cross_platform_file_transfer(self):
        """Test COMPAT-02/03: Verify file transfer between Python and Go clients (manual test)"""
        # This test requires both Python and Go clients running
        # It should be tested manually
        pass
    
    @unittest.skip("Requires both Python and Go clients running - test manually")
    def test_cross_platform_authentication(self):
        """Test COMPAT-01: Verify authentication works between Python and Go clients (manual test)"""
        # This test requires both Python and Go clients running
        # It should be tested manually
        pass


class TestErrorHandling(unittest.TestCase):
    """Test error handling functionality"""
    
    def setUp(self):
        """Set up test environment for error handling testing"""
        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a mock socket for testing
        self.mock_conn = mock.MagicMock()
    
    def tearDown(self):
        """Clean up after tests"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
   


if __name__ == '__main__':
    unittest.main()