import json
import os
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class ContactManager:
    """Manages trusted peer contacts and their verification status"""
    
    def __init__(self, peer_id):
        self.peer_id = peer_id
        self.storage_path = Path.home() / '.p2p-share' / 'metadata'
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.contacts_file = self.storage_path / 'trusted_contacts.json'
        self.contacts = {}
        self.load_contacts()
        logger.info(f"Contact manager initialized for peer {peer_id}")
    
    def load_contacts(self):
        """Load trusted contacts from storage"""
        try:
            if self.contacts_file.exists():
                with open(self.contacts_file, 'r') as f:
                    self.contacts = json.load(f)
                logger.info(f"Loaded {len(self.contacts)} trusted contacts from storage")
            else:
                self.contacts = {}
                self.save_contacts()
                logger.info("No existing contacts file, created new empty one")
        except Exception as e:
            logger.error(f"Error loading trusted contacts: {e}")
            self.contacts = {}
    
    def save_contacts(self):
        """Save trusted contacts to storage"""
        try:
            with open(self.contacts_file, 'w') as f:
                json.dump(self.contacts, f, indent=2)
            logger.debug(f"Saved {len(self.contacts)} trusted contacts to storage")
        except Exception as e:
            logger.error(f"Error saving trusted contacts: {e}")
    
    def add_trusted_contact(self, peer_id, peer_address, pubkey_pem, nickname=None):
        """Add or update a trusted contact"""
        self.contacts[peer_id] = {
            "peer_id": peer_id,
            "address": peer_address,
            "public_key": pubkey_pem,
            "nickname": nickname or f"Peer-{peer_id[:6]}",
            "verified_at": time.time(),
            "last_seen": time.time()
        }
        self.save_contacts()
        logger.info(f"Added trusted contact: {peer_id}")
        return True
    
    def remove_trusted_contact(self, peer_id):
        """Remove a trusted contact"""
        if peer_id in self.contacts:
            del self.contacts[peer_id]
            self.save_contacts()
            logger.info(f"Removed trusted contact: {peer_id}")
            return True
        return False
    
    def is_trusted(self, peer_id):
        """Check if a peer is trusted"""
        return peer_id in self.contacts
    
    def get_trusted_contact(self, peer_id):
        """Get information about a trusted contact"""
        return self.contacts.get(peer_id)
    
    def get_all_trusted_contacts(self):
        """Get all trusted contacts"""
        return self.contacts
    
    def update_last_seen(self, peer_id):
        """Update the last seen timestamp for a contact"""
        if peer_id in self.contacts:
            self.contacts[peer_id]["last_seen"] = time.time()
            self.save_contacts()
            return True
        return False
    
    def get_contact_by_address(self, address):
        """Find a contact by their network address"""
        for peer_id, contact in self.contacts.items():
            if contact["address"] == address:
                return contact
        return None