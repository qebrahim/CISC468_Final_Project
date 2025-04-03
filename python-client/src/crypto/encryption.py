import os
import base64
import hashlib
import secrets
from pathlib import Path
import logging

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

def generate_key():
    """Generate a random 32-byte key for AES-256"""
    return Fernet.generate_key()
def encrypt(data, key):
    """Encrypt data using AES-GCM"""
    # Generate a random 96-bit IV (nonce)
    iv = os.urandom(12)
    
    # Create encryptor
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Encrypt the data
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # Combine IV, ciphertext, and tag for storage or transmission
    return iv + encryptor.tag + ciphertext

def decrypt(encrypted_data, key):
    """Decrypt data using AES-GCM"""
    # Extract IV, tag, and ciphertext
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]  # GCM tag is 16 bytes
    ciphertext = encrypted_data[28:]
    
    # Create decryptor
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    return decryptor.update(ciphertext) + decryptor.finalize()

def generate_key():
    """Generate a random 256-bit key for AES"""
    return os.urandom(32)  # 32 bytes = 256 bits


def encrypt_file(file_path, output_path=None, passphrase=None):
    """
    Encrypt a file using AES-GCM
    
    Args:
        file_path: Path to the file to encrypt
        output_path: Path to save the encrypted file (default: file_path + '.enc')
        passphrase: Optional passphrase for encryption (generates a key if not provided)
        
    Returns:
        Path to the encrypted file
    """
    try:
        # Read the file
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        # Generate or derive key
        if passphrase:
            if isinstance(passphrase, str):
                passphrase = passphrase.encode('utf-8')
            key = hashlib.sha256(passphrase).digest()
        else:
            key = generate_key()
        
        # Encrypt the file data
        encrypted_data = encrypt(file_data, key)
        
        # Determine output path
        if not output_path:
            output_path = f"{file_path}.enc"
        
        # Create directory if it doesn't exist
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Write the encrypted file
        with open(output_path, 'wb') as file:
            file.write(encrypted_data)
        
        return output_path
    except Exception as e:
        logger.error(f"File encryption error: {e}")
        raise

def decrypt_file(encrypted_file_path, output_path=None, passphrase=None):
    """
    Decrypt a file using AES-GCM
    
    Args:
        encrypted_file_path: Path to the encrypted file
        output_path: Path to save the decrypted file (default: removes '.enc' extension)
        passphrase: Optional passphrase for decryption
        
    Returns:
        Path to the decrypted file
    """
    try:
        # Read the encrypted file
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = file.read()
        
        # Generate or derive key
        if passphrase:
            if isinstance(passphrase, str):
                passphrase = passphrase.encode('utf-8')
            key = hashlib.sha256(passphrase).digest()
        else:
            # If no passphrase, assume key was saved elsewhere
            raise ValueError("A passphrase is required for decryption")
        
        # Decrypt the file data
        decrypted_data = decrypt(encrypted_data, key)
        
        # Determine output path
        if not output_path:
            if encrypted_file_path.endswith('.enc'):
                output_path = encrypted_file_path[:-4]
            else:
                output_path = f"{encrypted_file_path}.dec"
        
        # Create directory if it doesn't exist
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Write the decrypted file
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)
        
        return output_path
    except Exception as e:
        logger.error(f"File decryption error: {e}")
        raise

def save_key(key, key_file):
    """Save the key to a file"""
    try:
        # Create directory if it doesn't exist
        key_dir = os.path.dirname(key_file)
        if key_dir and not os.path.exists(key_dir):
            os.makedirs(key_dir)
        
        # Write the key
        with open(key_file, 'wb') as file:
            file.write(key)
    except Exception as e:
        logger.error(f"Error saving key: {e}")
        raise

def load_key(key_file):
    """Load the key from a file"""
    try:
        with open(key_file, 'rb') as file:
            return file.read()
    except Exception as e:
        logger.error(f"Error loading key: {e}")
        raise

def derive_key(password, salt=None, length=32):
    """
    Derive a key from a password using PBKDF2
    
    Args:
        password: Password bytes
        salt: Salt bytes (generated if None)
        length: Length of the derived key in bytes
        
    Returns:
        Derived key bytes
    """
    try:
        if salt is None:
            salt = b'p2p-file-sharing-salt'  # Fixed salt for reproducibility
        
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password,
            salt,
            100000,  # 100,000 iterations
            length
        )
        return key
    except Exception as e:
        logger.error(f"Key derivation error: {e}")
        raise

def secure_store_file(input_file, passphrase=None):
    """
    Securely encrypt and store a file
    
    Args:
        input_file: Path to the file to store securely
        passphrase: Optional passphrase for encryption
        
    Returns:
        Path to the secure file
    """
    try:
        # Create secure storage directory
        secure_dir = Path.home() / '.p2p-share' / 'secure'
        secure_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate secure filename with random suffix
        base_name = os.path.basename(input_file)
        file_ext = os.path.splitext(base_name)[1]
        file_name = os.path.splitext(base_name)[0]
        random_suffix = secrets.token_urlsafe(8)
        secure_file_name = f"{file_name}_{random_suffix}{file_ext}.enc"
        output_file = secure_dir / secure_file_name
        
        # Generate passphrase if not provided
        if passphrase is None:
            passphrase = secrets.token_hex(16)
            # Save passphrase to key file
            key_dir = Path.home() / '.p2p-share' / 'keys' / 'secure'
            key_dir.mkdir(parents=True, exist_ok=True)
            key_file = key_dir / f"{secure_file_name}.key"
            with open(key_file, 'w') as f:
                f.write(passphrase)
            logger.info(f"Saved encryption key to {key_file}")
        
        # Encrypt the file
        encrypted_file = encrypt_file(input_file, str(output_file), passphrase)
        logger.info(f"File securely stored at {encrypted_file}")
        
        return encrypted_file
    except Exception as e:
        logger.error(f"Secure file storage error: {e}")
        raise

def secure_retrieve_file(encrypted_file, output_file=None, passphrase=None):
    """
    Decrypt and retrieve a securely stored file
    
    Args:
        encrypted_file: Path to the encrypted file
        output_file: Path to save the decrypted file
        passphrase: Optional passphrase for decryption
        
    Returns:
        Path to the decrypted file
    """
    try:
        # If no passphrase provided, try to load from key file
        if passphrase is None:
            file_name = os.path.basename(encrypted_file)
            key_file = Path.home() / '.p2p-share' / 'keys' / 'secure' / f"{file_name}.key"
            try:
                with open(key_file, 'r') as f:
                    passphrase = f.read().strip()
            except FileNotFoundError:
                raise ValueError(f"No passphrase provided and no key file found for {file_name}")
        
        # Decrypt the file
        decrypted_file = decrypt_file(encrypted_file, output_file, passphrase)
        logger.info(f"File securely retrieved to {decrypted_file}")
        
        return decrypted_file
    except Exception as e:
        logger.error(f"Secure file retrieval error: {e}")
        raise

def list_secure_files():
    """
    List all securely stored files
    
    Returns:
        List of encrypted file paths
    """
    try:
        # Get secure storage directory
        secure_dir = Path.home() / '.p2p-share' / 'secure'
        
        # Check if directory exists
        if not secure_dir.exists():
            return []
        
        # List all .enc files
        return [str(f) for f in secure_dir.glob('*.enc')]
    except Exception as e:
        logger.error(f"Error listing secure files: {e}")
        raise