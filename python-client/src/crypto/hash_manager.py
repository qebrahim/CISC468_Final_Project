import hashlib
import json
import os
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class HashManager:
    def __init__(self, peer_id):
        self.peer_id = peer_id
        self.storage_path = Path.home() / '.p2p-share' / 'metadata'
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.hash_file = self.storage_path / 'file_hashes.json'
        self.hashes = {}
        self.load_hashes()
        logger.info(f"Hash manager initialized for peer {peer_id}")

    def load_hashes(self):
        """Load file hashes from storage"""
        try:
            if self.hash_file.exists():
                with open(self.hash_file, 'r') as f:
                    self.hashes = json.load(f)
                logger.info(
                    f"Loaded {len(self.hashes)} file hashes from storage")
            else:
                self.hashes = {}
                self.save_hashes()
                logger.info("No existing hash file, created new empty one")
        except Exception as e:
            logger.error(f"Error loading file hashes: {e}")
            self.hashes = {}

    def save_hashes(self):
        """Save file hashes to storage"""
        try:
            with open(self.hash_file, 'w') as f:
                json.dump(self.hashes, f, indent=2)
            logger.debug(f"Saved {len(self.hashes)} file hashes to storage")
        except Exception as e:
            logger.error(f"Error saving file hashes: {e}")

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        try:
            hash_obj = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash: {e}")
            return None

    def add_file_hash(self, filename, file_path, origin_peer=None):
        """Add or update a file hash entry"""
        try:
            file_hash = self.calculate_file_hash(file_path)
            if not file_hash:
                return None

            file_size = os.path.getsize(file_path)

            if not origin_peer:
                origin_peer = self.peer_id

            basename = os.path.basename(filename)
            self.hashes[basename] = {
                "hash": file_hash,
                "size": file_size,
                "origin_peer": origin_peer,
                "last_verified": time.time()
            }
            self.save_hashes()
            logger.info(f"Added hash for file {basename}: {file_hash[:8]}...")
            return file_hash
        except Exception as e:
            logger.error(f"Error adding file hash: {e}")
            return None

    def get_file_hash(self, filename):
        """Get hash information for a file"""
        basename = os.path.basename(filename)
        result = self.hashes.get(basename, None)
        if result:
            logger.debug(f"Found hash for {basename}: {result['hash'][:8]}...")
        else:
            logger.debug(f"No hash found for {basename}")
        return result

    def verify_file_hash(self, file_path, expected_hash=None):
        """Verify file integrity against expected hash or stored hash"""
        try:
            basename = os.path.basename(file_path)

            # If no expected hash provided, check if we have it stored
            if not expected_hash and basename in self.hashes:
                expected_hash = self.hashes[basename]["hash"]

            if not expected_hash:
                logger.warning(
                    f"No hash available for verification of {basename}")
                return False

            actual_hash = self.calculate_file_hash(file_path)

            # Update last verification time if hash matches
            if actual_hash == expected_hash:
                logger.info(f"Hash verification successful for {basename}")
                if basename in self.hashes:
                    self.hashes[basename]["last_verified"] = time.time()
                    self.save_hashes()
                return True

            logger.warning(f"Hash verification failed for {basename}")
            return False
        except Exception as e:
            logger.error(f"Error verifying file hash: {e}")
            return False

    def get_all_file_hashes(self):
        """Get all file hashes as a dictionary"""
        return self.hashes

    def get_file_hashes_as_string(self, file_list):
        """Get hash info for a list of files in the format needed for FILE_LIST command"""
        result = []
        for filename in file_list:
            basename = os.path.basename(filename)
            hash_info = self.get_file_hash(basename)

            if hash_info:
                result.append(
                    f"{basename},{hash_info['hash']},{hash_info['size']}")
            else:
                # If we don't have hash info, just include the filename
                result.append(f"{basename},,")

        return ";".join(result)
