package crypto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// TrustedContact represents information about a trusted peer
type TrustedContact struct {
	PeerID     string  `json:"peer_id"`
	Address    string  `json:"address"`
	PublicKey  string  `json:"public_key"`
	Nickname   string  `json:"nickname"`
	VerifiedAt float64 `json:"verified_at"`
	LastSeen   float64 `json:"last_seen"`
}

// ContactManager manages trusted peer contacts
type ContactManager struct {
	PeerID       string
	StoragePath  string
	ContactsFile string
	Contacts     map[string]TrustedContact
}

// NewContactManager creates a new ContactManager
func NewContactManager(peerID string) (*ContactManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("error getting home directory: %v", err)
	}

	storagePath := filepath.Join(homeDir, ".p2p-share", "metadata")
	err = os.MkdirAll(storagePath, 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating metadata directory: %v", err)
	}

	contactsFile := filepath.Join(storagePath, "trusted_contacts.json")

	manager := &ContactManager{
		PeerID:       peerID,
		StoragePath:  storagePath,
		ContactsFile: contactsFile,
		Contacts:     make(map[string]TrustedContact),
	}

	// Load existing contacts if available
	err = manager.LoadContacts()
	if err != nil {
		fmt.Printf("Warning: Failed to load existing contacts: %v\n", err)
		// Continue with empty contacts map
	}

	return manager, nil
}

// LoadContacts loads trusted contacts from storage
func (cm *ContactManager) LoadContacts() error {
	// Check if file exists
	_, err := os.Stat(cm.ContactsFile)
	if os.IsNotExist(err) {
		// No contacts file yet, initialize with empty map
		cm.Contacts = make(map[string]TrustedContact)
		fmt.Printf("No contacts file found, initializing empty contacts map\n")
		return cm.SaveContacts()
	}

	cm.CleanupContactsByAddress()
	// Read contacts file
	data, err := os.ReadFile(cm.ContactsFile)
	if err != nil {
		return fmt.Errorf("error reading contacts file: %v", err)
	}

	fmt.Printf("Loaded contacts file: %s (size: %d bytes)\n", cm.ContactsFile, len(data))

	// Initialize contacts map if nil
	if cm.Contacts == nil {
		cm.Contacts = make(map[string]TrustedContact)
	}

	// Parse JSON
	if len(data) > 0 {
		// Create a temporary map to hold the contacts
		tempContacts := make(map[string]TrustedContact)
		err = json.Unmarshal(data, &tempContacts)
		if err != nil {
			// Try as an array for backward compatibility
			var contactList []TrustedContact
			err = json.Unmarshal(data, &contactList)
			if err != nil {
				return fmt.Errorf("error parsing contacts file: %v", err)
			}

			// Convert array to map
			for _, contact := range contactList {
				tempContacts[contact.PeerID] = contact
			}
		}

		// Update the actual contacts map
		cm.Contacts = tempContacts
		fmt.Printf("Parsed %d contacts from file\n", len(cm.Contacts))
	}

	return nil
}

// SaveContacts saves trusted contacts to storage
func (cm *ContactManager) SaveContacts() error {
	// Ensure directory exists
	err := os.MkdirAll(filepath.Dir(cm.ContactsFile), 0755)
	if err != nil {
		return fmt.Errorf("error creating directory: %v", err)
	}

	// Debug info
	fmt.Printf("Saving %d contacts to %s\n", len(cm.Contacts), cm.ContactsFile)

	// Make sure Contacts is initialized
	if cm.Contacts == nil {
		cm.Contacts = make(map[string]TrustedContact)
	}

	data, err := json.MarshalIndent(cm.Contacts, "", "  ")
	if err != nil {
		return fmt.Errorf("error serializing contacts: %v", err)
	}

	// Write to a temporary file first
	tempFile := cm.ContactsFile + ".tmp"
	err = os.WriteFile(tempFile, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing temporary contacts file: %v", err)
	}

	// Rename temp file to actual file (atomic operation)
	err = os.Rename(tempFile, cm.ContactsFile)
	if err != nil {
		return fmt.Errorf("error renaming contacts file: %v", err)
	}

	// Verify save
	if fileInfo, err := os.Stat(cm.ContactsFile); err == nil {
		fmt.Printf("Contacts file saved: %s (size: %d bytes)\n", cm.ContactsFile, fileInfo.Size())
	}

	return nil
}

// AddTrustedContact adds or updates a trusted contact
func (cm *ContactManager) AddTrustedContact(peerID, peerAddress, pubkeyPEM, nickname string) bool {
	if nickname == "" {
		nickname = fmt.Sprintf("Peer-%s", peerID[:6])
	}

	// Debug
	fmt.Printf("Adding trusted contact: ID=%s, Address=%s, Nickname=%s\n",
		peerID, peerAddress, nickname)

	// Ensure Contacts is initialized
	if cm.Contacts == nil {
		cm.Contacts = make(map[string]TrustedContact)
	}

	cm.Contacts[peerID] = TrustedContact{
		PeerID:     peerID,
		Address:    peerAddress,
		PublicKey:  pubkeyPEM,
		Nickname:   nickname,
		VerifiedAt: float64(time.Now().Unix()),
		LastSeen:   float64(time.Now().Unix()),
	}

	// Debug after adding
	fmt.Printf("Contact added, current contacts: %+v\n", cm.Contacts)

	err := cm.SaveContacts()
	if err != nil {
		fmt.Printf("Warning: Failed to save contacts: %v\n", err)
		return false
	}

	fmt.Printf("Added trusted contact: %s\n", peerID)
	return true
}

// RemoveTrustedContact removes a trusted contact
func (cm *ContactManager) RemoveTrustedContact(peerID string) bool {
	if _, exists := cm.Contacts[peerID]; exists {
		delete(cm.Contacts, peerID)
		cm.SaveContacts()
		fmt.Printf("Removed trusted contact: %s\n", peerID)
		return true
	}
	return false
}

// IsTrusted checks if a peer is trusted
func (cm *ContactManager) IsTrusted(peerID string) bool {
	_, exists := cm.Contacts[peerID]
	return exists
}

// GetTrustedContact gets information about a trusted contact
func (cm *ContactManager) GetTrustedContact(peerID string) (TrustedContact, bool) {
	contact, exists := cm.Contacts[peerID]
	return contact, exists
}

// GetAllTrustedContacts gets all trusted contacts
func (cm *ContactManager) GetAllTrustedContacts() map[string]TrustedContact {
	return cm.Contacts
}

// UpdateLastSeen updates the last seen timestamp for a contact
func (cm *ContactManager) UpdateLastSeen(peerID string) bool {
	if contact, exists := cm.Contacts[peerID]; exists {
		contact.LastSeen = float64(time.Now().Unix())
		cm.Contacts[peerID] = contact
		cm.SaveContacts()
		return true
	}
	return false
}

// GetContactByAddress finds a contact by their network address
func (cm *ContactManager) GetContactByAddress(address string) (TrustedContact, bool) {
	fmt.Printf("Looking for contact with address: %s\n", address) // Debug line
	fmt.Printf("Current contacts: %+v\n", cm.Contacts)            // Debug line

	for _, contact := range cm.Contacts {
		if contact.Address == address {
			return contact, true
		}
	}
	return TrustedContact{}, false
}

// Add this helper function
func directlySaveContact(peerID, address, publicKey string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error getting home directory: %v", err)
	}

	storagePath := filepath.Join(homeDir, ".p2p-share", "metadata")
	err = os.MkdirAll(storagePath, 0755)
	if err != nil {
		return fmt.Errorf("error creating metadata directory: %v", err)
	}

	contactsFile := filepath.Join(storagePath, "trusted_contacts.json")

	// Read existing contacts
	var contacts map[string]TrustedContact
	data, err := os.ReadFile(contactsFile)
	if err != nil || len(data) <= 2 {
		// File doesn't exist or is empty, create new map
		contacts = make(map[string]TrustedContact)
	} else {
		// Parse existing contacts
		if err := json.Unmarshal(data, &contacts); err != nil {
			// If parsing fails, create new map
			contacts = make(map[string]TrustedContact)
		}
	}

	// Add the contact
	contacts[peerID] = TrustedContact{
		PeerID:     peerID,
		Address:    address,
		PublicKey:  publicKey,
		Nickname:   fmt.Sprintf("Peer-%s", peerID[:6]),
		VerifiedAt: float64(time.Now().Unix()),
		LastSeen:   float64(time.Now().Unix()),
	}

	// Write back to file
	newData, err := json.MarshalIndent(contacts, "", "  ")
	if err != nil {
		return fmt.Errorf("error serializing contacts: %v", err)
	}

	err = os.WriteFile(contactsFile, newData, 0644)
	if err != nil {
		return fmt.Errorf("error writing contacts file: %v", err)
	}

	fmt.Printf("Directly saved contact %s to file\n", peerID)
	return nil
}

// Add this function to internal/crypto/contact_manager.go

// CleanupContactsByAddress removes duplicate contacts that share the same address
func (cm *ContactManager) CleanupContactsByAddress() {
	// Create a map to track addresses
	addressMap := make(map[string]string) // address -> first peerID
	duplicates := make([]string, 0)

	// First pass: identify duplicates
	for peerID, contact := range cm.Contacts {
		existingPeerID, exists := addressMap[contact.Address]
		if exists {
			// This is a duplicate address, if it's a newer contact keep it
			existingContact := cm.Contacts[existingPeerID]
			if contact.VerifiedAt > existingContact.VerifiedAt {
				// This is newer, mark the older one as duplicate
				duplicates = append(duplicates, existingPeerID)
				addressMap[contact.Address] = peerID
			} else {
				// The existing one is newer, mark this one as duplicate
				duplicates = append(duplicates, peerID)
			}
		} else {
			// First time seeing this address
			addressMap[contact.Address] = peerID
		}
	}

	// Second pass: remove duplicates
	for _, peerID := range duplicates {
		delete(cm.Contacts, peerID)
		fmt.Printf("Removed duplicate contact: %s\n", peerID)
	}

	// Save the cleaned contacts
	if len(duplicates) > 0 {
		cm.SaveContacts()
		fmt.Printf("Cleaned up %d duplicate contacts\n", len(duplicates))
	}
}
