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
	if _, err := os.Stat(cm.ContactsFile); os.IsNotExist(err) {
		// No contacts file yet, initialize with empty map
		return cm.SaveContacts()
	}

	// Read contacts file
	data, err := os.ReadFile(cm.ContactsFile)
	if err != nil {
		return fmt.Errorf("error reading contacts file: %v", err)
	}

	// Parse JSON
	if len(data) > 0 {
		err = json.Unmarshal(data, &cm.Contacts)
		if err != nil {
			return fmt.Errorf("error parsing contacts file: %v", err)
		}
	}

	return nil
}

// SaveContacts saves trusted contacts to storage
func (cm *ContactManager) SaveContacts() error {
	data, err := json.MarshalIndent(cm.Contacts, "", "  ")
	if err != nil {
		return fmt.Errorf("error serializing contacts: %v", err)
	}

	err = os.WriteFile(cm.ContactsFile, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing contacts file: %v", err)
	}

	return nil
}

// AddTrustedContact adds or updates a trusted contact
func (cm *ContactManager) AddTrustedContact(peerID, peerAddress, pubkeyPEM, nickname string) bool {
	if nickname == "" {
		nickname = fmt.Sprintf("Peer-%s", peerID[:6])
	}

	cm.Contacts[peerID] = TrustedContact{
		PeerID:     peerID,
		Address:    peerAddress,
		PublicKey:  pubkeyPEM,
		Nickname:   nickname,
		VerifiedAt: float64(time.Now().Unix()),
		LastSeen:   float64(time.Now().Unix()),
	}

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
	for _, contact := range cm.Contacts {
		if contact.Address == address {
			return contact, true
		}
	}
	return TrustedContact{}, false
}
