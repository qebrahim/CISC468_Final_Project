package crypto

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Global variables for state management
var (
	contactManager       *ContactManager
	authentication       *PeerAuthentication
	pendingMutex         sync.RWMutex
	pendingVerifications = make(map[string]PendingVerification)
)

// Global map to store public keys by peer ID
var peerPublicKeys = make(map[string]string)
var peerPublicKeysMutex sync.RWMutex

// PendingVerification represents a pending authentication request
type PendingVerification struct {
	ContactData TrustedContact
	ChallengeID string
	Signature   string
	Timestamp   float64
	Conn        net.Conn
}

// InitAuthentication initializes the authentication protocol
func InitAuthentication(peerID string, cm *ContactManager, auth *PeerAuthentication) {
	contactManager = cm
	authentication = auth

	// Set the global contact manager for other modules
	SetContactManager(cm)

	fmt.Printf("Authentication protocol initialized for peer %s\n", peerID)
}

// StorePublicKey stores a peer's public key for later use
func StorePublicKey(peerID, publicKey string) {
	peerPublicKeysMutex.Lock()
	defer peerPublicKeysMutex.Unlock()
	peerPublicKeys[peerID] = publicKey
	fmt.Printf("Stored public key for peer %s (length: %d)\n", peerID, len(publicKey))
}

// GetPublicKey retrieves a peer's public key if available
func GetPublicKey(peerID string) (string, bool) {
	peerPublicKeysMutex.RLock()
	defer peerPublicKeysMutex.RUnlock()
	key, exists := peerPublicKeys[peerID]
	return key, exists
}

// HandleAuthMessage processes authentication protocol messages
func HandleAuthMessage(conn net.Conn, addr string, message string) error {
	parts := strings.SplitN(message, ":", 3)
	if len(parts) < 3 {
		return fmt.Errorf("invalid auth message format: %s", message)
	}

	authCommand := parts[1]
	payload := parts[2]

	switch authCommand {
	case "HELLO":
		return handleHello(conn, addr, payload)
	case "CHALLENGE":
		return handleChallenge(conn, addr, payload)
	case "RESPONSE":
		return handleResponse(conn, addr, payload)
	case "VERIFY":
		return handleVerify(conn, addr, payload)
	case "TRUST":
		return handleTrust(conn, addr, payload)
	default:
		return fmt.Errorf("unknown auth command: %s", authCommand)
	}
}

// handleHello processes the initial authentication handshake
func handleHello(conn net.Conn, addr string, payload string) error {
	// Parse the payload
	var data map[string]interface{}
	err := json.Unmarshal([]byte(payload), &data)
	if err != nil {
		return fmt.Errorf("error parsing HELLO message: %v", err)
	}

	peerID, ok := data["peer_id"].(string)
	if !ok {
		return fmt.Errorf("missing peer_id in HELLO message")
	}

	pubkey, ok := data["public_key"].(string)
	if !ok {
		return fmt.Errorf("missing public_key in HELLO message")
	}

	StorePublicKey(peerID, pubkey)
	fmt.Printf("Stored public key from HELLO message (peer: %s)\n", peerID)

	fmt.Printf("Received HELLO from peer %s\n", peerID)
	// print pubkey
	fmt.Printf("Public Key: %s\n", pubkey)

	// Generate a challenge for the peer
	challengeID, challengeB64, err := authentication.CreateChallenge(peerID)
	if err != nil {
		return fmt.Errorf("error creating challenge: %v", err)
	}

	// Send challenge
	response := map[string]interface{}{
		"peer_id":      authentication.PeerID,
		"challenge_id": challengeID,
		"challenge":    challengeB64,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("error encoding challenge: %v", err)
	}

	_, err = conn.Write([]byte(fmt.Sprintf("AUTH:CHALLENGE:%s", responseJSON)))
	if err != nil {
		return fmt.Errorf("error sending challenge: %v", err)
	}

	fmt.Printf("Sent challenge to peer %s\n", peerID)
	return nil
}

// handleChallenge processes an authentication challenge from a peer
func handleChallenge(conn net.Conn, addr string, payload string) error {
	// Parse the payload
	var data map[string]interface{}
	err := json.Unmarshal([]byte(payload), &data)
	if err != nil {
		return fmt.Errorf("error parsing CHALLENGE message: %v", err)
	}

	peerID, ok := data["peer_id"].(string)
	if !ok {
		return fmt.Errorf("missing peer_id in CHALLENGE message")
	}

	challengeID, ok := data["challenge_id"].(string)
	if !ok {
		return fmt.Errorf("missing challenge_id in CHALLENGE message")
	}

	challenge, ok := data["challenge"].(string)
	if !ok {
		return fmt.Errorf("missing challenge in CHALLENGE message")
	}

	fmt.Printf("Received CHALLENGE from peer %s\n", peerID)

	// Sign the challenge
	signature, err := authentication.SignChallenge(challenge)
	if err != nil {
		return fmt.Errorf("error signing challenge: %v", err)
	}

	// Send response with our signature and public key
	response := map[string]interface{}{
		"peer_id":      authentication.PeerID,
		"challenge_id": challengeID,
		"signature":    signature,
		"public_key":   authentication.GetPublicKeyPEM(),
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("error encoding response: %v", err)
	}

	_, err = conn.Write([]byte(fmt.Sprintf("AUTH:RESPONSE:%s", responseJSON)))
	if err != nil {
		return fmt.Errorf("error sending response: %v", err)
	}

	fmt.Printf("Sent challenge response to peer %s\n", peerID)
	return nil
}

// handleResponse processes a challenge response from a peer
func handleResponse(conn net.Conn, addr string, payload string) error {
	// Parse the payload
	var data map[string]interface{}
	err := json.Unmarshal([]byte(payload), &data)
	if err != nil {
		return fmt.Errorf("error parsing RESPONSE message: %v", err)
	}

	peerID, ok := data["peer_id"].(string)
	if !ok {
		return fmt.Errorf("missing peer_id in RESPONSE message")
	}

	challengeID, ok := data["challenge_id"].(string)
	if !ok {
		return fmt.Errorf("missing challenge_id in RESPONSE message")
	}

	signature, ok := data["signature"].(string)
	if !ok {
		return fmt.Errorf("missing signature in RESPONSE message")
	}

	pubkey, ok := data["public_key"].(string)
	if !ok {
		return fmt.Errorf("missing public_key in RESPONSE message")
	}

	// Store the public key for later use
	StorePublicKey(peerID, pubkey)
	fmt.Printf("Stored public key from RESPONSE message (peer: %s)\n", peerID)

	// Store the peer's public key temporarily for verification
	hostPort := strings.Split(addr, ":")
	if len(hostPort) < 2 {
		return fmt.Errorf("invalid address format: %s", addr)
	}
	peerAddr := fmt.Sprintf("%s:12345", hostPort[0]) // Use standard port for storage

	// Store temporary contact info
	tempContact := TrustedContact{
		PeerID:    peerID,
		Address:   peerAddr,
		PublicKey: pubkey,
	}

	// Important: At this point, we need to ask the user for trust confirmation
	fmt.Printf("\nNew peer attempting to authenticate:\n")
	fmt.Printf("  Peer ID: %s\n", peerID)
	fmt.Printf("  Address: %s\n", peerAddr)
	fmt.Println()
	fmt.Print("Do you want to verify and trust this peer? (y/n): ")

	// Send a VERIFY message to indicate we're in the verification process
	// This is just to acknowledge the response while we wait for user input
	verifyMsg := map[string]interface{}{
		"peer_id": authentication.PeerID,
		"status":  "verifying",
	}

	verifyJSON, err := json.Marshal(verifyMsg)
	if err != nil {
		return fmt.Errorf("error encoding verify message: %v", err)
	}

	_, err = conn.Write([]byte(fmt.Sprintf("AUTH:VERIFY:%s", verifyJSON)))
	if err != nil {
		return fmt.Errorf("error sending verify message: %v", err)
	}

	// Store the verification request for later processing by the user
	StoreVerificationRequest(peerID, tempContact, challengeID, signature, conn)

	return nil
}

// handleVerify processes verification status updates
func handleVerify(conn net.Conn, addr string, payload string) error {
	// Parse the payload
	var data map[string]interface{}
	err := json.Unmarshal([]byte(payload), &data)
	if err != nil {
		return fmt.Errorf("error parsing VERIFY message: %v", err)
	}

	peerID, ok := data["peer_id"].(string)
	if !ok {
		return fmt.Errorf("missing peer_id in VERIFY message")
	}

	status, ok := data["status"].(string)
	if !ok {
		return fmt.Errorf("missing status in VERIFY message")
	}

	fmt.Printf("Received VERIFY from peer %s with status: %s\n", peerID, status)

	if status == "verified" {
		fmt.Printf("\nPeer %s has verified your identity!\n", peerID)

		// We don't automatically trust them back, that's a separate user decision
		// But we acknowledge their verification
		response := map[string]interface{}{
			"peer_id": authentication.PeerID,
			"status":  "acknowledged",
		}

		responseJSON, err := json.Marshal(response)
		if err != nil {
			return fmt.Errorf("error encoding acknowledgment: %v", err)
		}

		_, err = conn.Write([]byte(fmt.Sprintf("AUTH:VERIFY:%s", responseJSON)))
		if err != nil {
			return fmt.Errorf("error sending acknowledgment: %v", err)
		}

	} else if status == "rejected" {
		fmt.Printf("\nPeer %s has rejected the authentication request.\n", peerID)
	} else if status == "verifying" {
		fmt.Printf("Peer %s is considering our authentication request\n", peerID)
	}

	return nil
}

// handleTrust processes trust status updates
func handleTrust(conn net.Conn, addr string, payload string) error {
	// Parse the payload
	var data map[string]interface{}
	err := json.Unmarshal([]byte(payload), &data)
	if err != nil {
		return fmt.Errorf("error parsing TRUST message: %v", err)
	}

	peerID, ok := data["peer_id"].(string)
	if !ok {
		return fmt.Errorf("missing peer_id in TRUST message")
	}

	// Check if this is a trust status update or acknowledgment
	if trustedVal, ok := data["trusted"].(bool); ok {
		if trustedVal {
			fmt.Printf("\nPeer %s has added you as a trusted contact!\n", peerID)
		} else {
			fmt.Printf("\nPeer %s has removed you as a trusted contact.\n", peerID)
		}

		// Acknowledge the trust status update
		response := map[string]interface{}{
			"peer_id": authentication.PeerID,
			"status":  "acknowledged",
		}

		responseJSON, err := json.Marshal(response)
		if err != nil {
			return fmt.Errorf("error encoding acknowledgment: %v", err)
		}

		_, err = conn.Write([]byte(fmt.Sprintf("AUTH:TRUST:%s", responseJSON)))
		if err != nil {
			return fmt.Errorf("error sending acknowledgment: %v", err)
		}

		// If the peer trusts us, we should try to reciprocate
		if trustedVal {
			// Parse out host for address
			hostPort := strings.Split(addr, ":")
			if len(hostPort) >= 1 {
				peerAddr := fmt.Sprintf("%s:12345", hostPort[0]) // Use standard port

				// First check if we already have this peer
				if !contactManager.IsTrusted(peerID) {
					// We may need the peer's public key
					for id, verif := range pendingVerifications {
						if id == peerID {
							// We have the peer's public key from a verification
							contactManager.AddTrustedContact(
								peerID,
								peerAddr,
								verif.ContactData.PublicKey,
								fmt.Sprintf("Peer-%s", peerID[:6]),
							)
							fmt.Printf("Automatically added %s to trusted contacts based on their trust signal\n", peerID)
							break
						}
					}
				} else {
					// Update last seen time
					contactManager.UpdateLastSeen(peerID)
				}

				// Ensure the contact is saved
				contactManager.SaveContacts()
			}
		}
	} else if status, ok := data["status"].(string); ok {
		// This is an acknowledgment of our trust message
		fmt.Printf("Received trust acknowledgment from peer %s: %s\n", peerID, status)
	} else {
		fmt.Printf("Missing trusted or status field in TRUST message from %s\n", peerID)
	}

	return nil
}

// StoreVerificationRequest stores a verification request for later processing
func StoreVerificationRequest(peerID string, contactData TrustedContact, challengeID, signature string, conn net.Conn) {
	pendingMutex.Lock()
	defer pendingMutex.Unlock()

	pendingVerifications[peerID] = PendingVerification{
		ContactData: contactData,
		ChallengeID: challengeID,
		Signature:   signature,
		Timestamp:   float64(time.Now().Unix()),
		Conn:        conn,
	}

	fmt.Printf("Stored verification request from peer %s for user confirmation\n", peerID)
}

// GetPendingVerifications returns all pending verification requests
func GetPendingVerifications() map[string]PendingVerification {
	pendingMutex.RLock()
	defer pendingMutex.RUnlock()

	// Make a copy to avoid concurrent modification issues
	result := make(map[string]PendingVerification)
	for k, v := range pendingVerifications {
		result[k] = v
	}

	// Clean up old requests (older than 5 minutes)
	currentTime := float64(time.Now().Unix())
	for peerID, data := range result {
		if currentTime-data.Timestamp > 300 { // 5 minutes
			delete(result, peerID)
			delete(pendingVerifications, peerID)
		}
	}

	return result
}

// ProcessVerificationResponse processes user's response to a verification request
func ProcessVerificationResponse(peerID string, trusted bool) bool {
	pendingMutex.Lock()
	defer pendingMutex.Unlock()

	verification, exists := pendingVerifications[peerID]
	if !exists {
		fmt.Printf("No pending verification for peer %s\n", peerID)
		return false
	}

	conn := verification.Conn
	challengeID := verification.ChallengeID
	signature := verification.Signature
	contactData := verification.ContactData

	if trusted {
		// Verify the signature
		isValid, err := authentication.VerifySignature(peerID, challengeID, signature, contactData.PublicKey)

		if err != nil {
			fmt.Printf("Error verifying signature: %v\n", err)
			// Failed verification
			if conn != nil {
				verifyMsg := map[string]interface{}{
					"peer_id": authentication.PeerID,
					"status":  "rejected",
				}

				verifyJSON, err := json.Marshal(verifyMsg)
				if err == nil {
					conn.Write([]byte(fmt.Sprintf("AUTH:VERIFY:%s", verifyJSON)))
				}
			}
			delete(pendingVerifications, peerID)
			return false
		}

		if isValid {
			// Add to trusted contacts with detailed logging
			fmt.Printf("Signature verified. Adding peer %s to trusted contacts\n", peerID)
			fmt.Printf("Contact address: %s\n", contactData.Address)
			fmt.Printf("Public key length: %d\n", len(contactData.PublicKey))

			// Make sure we have the contact manager
			if contactManager == nil {
				fmt.Printf("ERROR: Contact manager not initialized!\n")
				delete(pendingVerifications, peerID)
				return false
			}

			// Remove any existing entry first
			if contactManager.Contacts == nil {
				contactManager.Contacts = make(map[string]TrustedContact)
			}
			delete(contactManager.Contacts, peerID)

			// Create new entry with all required fields
			contactManager.Contacts[peerID] = TrustedContact{
				PeerID:     peerID,
				Address:    contactData.Address,
				PublicKey:  contactData.PublicKey,
				Nickname:   fmt.Sprintf("Peer-%s", peerID[:6]),
				VerifiedAt: float64(time.Now().Unix()),
				LastSeen:   float64(time.Now().Unix()),
			}

			// Debug - check how many contacts we have now
			fmt.Printf("Updated contacts, now have %d contacts\n", len(contactManager.Contacts))
			for id, contact := range contactManager.Contacts {
				fmt.Printf("- Contact: %s at %s\n", id, contact.Address)
			}

			// Force save to disk
			err = contactManager.SaveContacts()
			if err != nil {
				fmt.Printf("Error saving contacts: %v\n", err)
			} else {
				fmt.Printf("Saved %d contacts to %s\n", len(contactManager.Contacts), contactManager.ContactsFile)

				// Dump the contents of the file to verify it was saved correctly
				fileData, readErr := os.ReadFile(contactManager.ContactsFile)
				if readErr == nil {
					fmt.Printf("File contents: %s\n", string(fileData))
				} else {
					fmt.Printf("Error reading contacts file: %v\n", readErr)
				}
			}

			// Notify the peer that they are now trusted
			if conn != nil {
				// Send verification confirmation
				verifyMsg := map[string]interface{}{
					"peer_id": authentication.PeerID,
					"status":  "verified",
				}

				verifyJSON, err := json.Marshal(verifyMsg)
				if err == nil {
					conn.Write([]byte(fmt.Sprintf("AUTH:VERIFY:%s", verifyJSON)))
				}

				// Also send trust notification
				trustMsg := map[string]interface{}{
					"peer_id": authentication.PeerID,
					"trusted": true,
				}

				trustJSON, err := json.Marshal(trustMsg)
				if err == nil {
					conn.Write([]byte(fmt.Sprintf("AUTH:TRUST:%s", trustJSON)))
				}
			}

			fmt.Printf("Peer %s verified and added to trusted contacts!\n", peerID)
			delete(pendingVerifications, peerID)
			return true
		} else {
			// Invalid signature
			fmt.Printf("Warning: Signature verification failed for peer %s!\n", peerID)

			// Notify the peer about rejection
			if conn != nil {
				verifyMsg := map[string]interface{}{
					"peer_id": authentication.PeerID,
					"status":  "rejected",
				}

				verifyJSON, err := json.Marshal(verifyMsg)
				if err == nil {
					conn.Write([]byte(fmt.Sprintf("AUTH:VERIFY:%s", verifyJSON)))
				}
			}

			delete(pendingVerifications, peerID)
			return false
		}
	} else {
		// User rejected the verification
		fmt.Printf("Rejected verification request from peer %s\n", peerID)

		// Notify the peer about rejection
		if conn != nil {
			verifyMsg := map[string]interface{}{
				"peer_id": authentication.PeerID,
				"status":  "rejected",
			}

			verifyJSON, err := json.Marshal(verifyMsg)
			if err == nil {
				conn.Write([]byte(fmt.Sprintf("AUTH:VERIFY:%s", verifyJSON)))
			}
		}

		delete(pendingVerifications, peerID)
		return false
	}
}

func CheckPeerAuthenticated(peerAddr string) bool {
	if contactManager == nil {
		return false
	}

	// Extract host and use standard port for lookup
	parts := strings.Split(peerAddr, ":")
	if len(parts) < 2 {
		return false
	}

	standardAddr := fmt.Sprintf("%s:12345", parts[0])
	_, found := contactManager.GetContactByAddress(standardAddr)
	return found
}

// InitiateAuthentication initiates the authentication process with a peer
func InitiateAuthentication(peerAddr string) (bool, error) {
	// Parse address
	hostPort := strings.Split(peerAddr, ":")
	if len(hostPort) != 2 {
		return false, fmt.Errorf("invalid address format: %s", peerAddr)
	}

	host := hostPort[0]
	port := hostPort[1]

	fmt.Printf("Initiating authentication with peer at %s:%s\n", host, port)

	// Create connection
	conn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false, fmt.Errorf("error connecting to %s: %v", peerAddr, err)
	}

	// Send HELLO message with our ID and public key
	helloMsg := map[string]interface{}{
		"peer_id":    authentication.PeerID,
		"public_key": authentication.GetPublicKeyPEM(),
	}

	helloJSON, err := json.Marshal(helloMsg)
	if err != nil {
		conn.Close()
		return false, fmt.Errorf("error encoding HELLO message: %v", err)
	}

	_, err = conn.Write([]byte(fmt.Sprintf("AUTH:HELLO:%s", helloJSON)))
	if err != nil {
		conn.Close()
		return false, fmt.Errorf("error sending HELLO message: %v", err)
	}

	fmt.Printf("Sent HELLO to %s\n", peerAddr)

	// Start a goroutine to handle the rest of the authentication process
	go handleAuthResponses(conn, peerAddr)

	return true, nil
}

// handleAuthResponses handles responses during the authentication process
func handleAuthResponses(conn net.Conn, peerAddr string) {
	defer conn.Close()

	buffer := make([]byte, 8192)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Printf("Connection closed by peer %s: %v\n", peerAddr, err)
			return
		}

		message := string(buffer[:n])
		parts := strings.SplitN(message, ":", 3)
		if len(parts) < 3 || parts[0] != "AUTH" {
			fmt.Printf("Invalid auth response from %s: %s\n", peerAddr, message)
			continue
		}

		authCommand := parts[1]
		payload := parts[2]

		switch authCommand {
		case "CHALLENGE":
			handleAuthChallenge(conn, peerAddr, payload)
		case "RESPONSE":
			handleAuthResponse(conn, peerAddr, payload)
		case "VERIFY":
			handleAuthVerify(conn, peerAddr, payload)
		case "TRUST":
			handleAuthTrust(conn, peerAddr, payload)
		default:
			fmt.Printf("Unknown auth response command: %s\n", authCommand)
		}
	}
}

// handleAuthChallenge handles a challenge received during authentication
func handleAuthChallenge(conn net.Conn, peerAddr string, payload string) {
	// Parse the payload
	var data map[string]interface{}
	err := json.Unmarshal([]byte(payload), &data)
	if err != nil {
		fmt.Printf("Error parsing CHALLENGE message: %v\n", err)
		return
	}

	// After successfully parsing the peer ID
	peerID, ok := data["peer_id"].(string)
	if !ok {
		fmt.Printf("Missing peer_id in CHALLENGE message\n")
		return
	}

	challengeID, ok := data["challenge_id"].(string)
	if !ok {
		fmt.Printf("Missing challenge_id in CHALLENGE message\n")
		return
	}

	challenge, ok := data["challenge"].(string)
	if !ok {
		fmt.Printf("Missing challenge in CHALLENGE message\n")
		return
	}

	fmt.Printf("Received CHALLENGE from peer %s\n", peerID)

	StorePublicKey(peerID, authentication.GetPublicKeyPEM())
	fmt.Printf("Stored our public key for peer %s\n", peerID)

	// Sign the challenge
	signature, err := authentication.SignChallenge(challenge)
	if err != nil {
		fmt.Printf("Error signing challenge: %v\n", err)
		return
	}

	// Send response with our signature and public key
	response := map[string]interface{}{
		"peer_id":      authentication.PeerID,
		"challenge_id": challengeID,
		"signature":    signature,
		"public_key":   authentication.GetPublicKeyPEM(),
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		fmt.Printf("Error encoding response: %v\n", err)
		return
	}

	_, err = conn.Write([]byte(fmt.Sprintf("AUTH:RESPONSE:%s", responseJSON)))
	if err != nil {
		fmt.Printf("Error sending response: %v\n", err)
		return
	}

	fmt.Printf("Sent challenge response to peer %s\n", peerID)

	// Parse out host and port for address
	hostPort := strings.Split(peerAddr, ":")
	if len(hostPort) < 2 {
		fmt.Printf("Invalid address format: %s\n", peerAddr)
		return
	}

	standardAddr := fmt.Sprintf("%s:12345", hostPort[0]) // Use standard port

	// Print information for user verification
	fmt.Printf("\nPending authentication with peer:\n")
	fmt.Printf("  Peer ID: %s\n", peerID)
	fmt.Printf("  Address: %s\n", standardAddr)
	fmt.Println()
	fmt.Printf("Awaiting verification from peer...\n")
}

// handleAuthResponse handles a response to our challenge
func handleAuthResponse(conn net.Conn, peerAddr string, payload string) {
	// Parse the payload
	var data map[string]interface{}
	err := json.Unmarshal([]byte(payload), &data)
	if err != nil {
		fmt.Printf("Error parsing RESPONSE message: %v\n", err)
		return
	}

	peerID, ok := data["peer_id"].(string)
	if !ok {
		fmt.Printf("Missing peer_id in RESPONSE message\n")
		return
	}

	challengeID, ok := data["challenge_id"].(string)
	if !ok {
		fmt.Printf("Missing challenge_id in RESPONSE message\n")
		return
	}

	signature, ok := data["signature"].(string)
	if !ok {
		fmt.Printf("Missing signature in RESPONSE message\n")
		return
	}

	pubkey, ok := data["public_key"].(string)
	if !ok {
		fmt.Printf("Missing public_key in RESPONSE message\n")
		return
	}

	fmt.Printf("Received RESPONSE from peer %s\n", peerID)

	// Parse out host and port for address
	hostPort := strings.Split(peerAddr, ":")
	if len(hostPort) < 2 {
		fmt.Printf("Invalid address format: %s\n", peerAddr)
		return
	}

	standardAddr := fmt.Sprintf("%s:12345", hostPort[0]) // Use standard port

	// Store temporary contact info
	tempContact := TrustedContact{
		PeerID:    peerID,
		Address:   standardAddr,
		PublicKey: pubkey,
	}

	// Important: At this point, we need to ask the user for trust confirmation
	fmt.Printf("\nPeer has responded to authentication challenge:\n")
	fmt.Printf("  Peer ID: %s\n", peerID)
	fmt.Printf("  Address: %s\n", standardAddr)
	fmt.Println()
	fmt.Printf("Do you want to verify and trust this peer? (y/n): ")

	// Send a VERIFY message to indicate we're in the verification process
	verifyMsg := map[string]interface{}{
		"peer_id": authentication.PeerID,
		"status":  "verifying",
	}

	verifyJSON, err := json.Marshal(verifyMsg)
	if err != nil {
		fmt.Printf("Error encoding verify message: %v\n", err)
		return
	}

	_, err = conn.Write([]byte(fmt.Sprintf("AUTH:VERIFY:%s", verifyJSON)))
	if err != nil {
		fmt.Printf("Error sending verify message: %v\n", err)
		return
	}

	// Store the verification data for user decision
	StoreVerificationRequest(peerID, tempContact, challengeID, signature, conn)
}

// handleAuthVerify handles verification status update
func handleAuthVerify(conn net.Conn, peerAddr string, payload string) {
	// Parse the payload
	var data map[string]interface{}
	err := json.Unmarshal([]byte(payload), &data)
	if err != nil {
		fmt.Printf("Error parsing VERIFY message: %v\n", err)
		return
	}

	peerID, ok := data["peer_id"].(string)
	if !ok {
		fmt.Printf("Missing peer_id in VERIFY message\n")
		return
	}

	status, ok := data["status"].(string)
	if !ok {
		fmt.Printf("Missing status in VERIFY message\n")
		return
	}

	fmt.Printf("Received VERIFY from peer %s with status: %s\n", peerID, status)

	if status == "verified" {
		fmt.Printf("\nPeer %s has verified your identity and trusts you!\n", peerID)

		// Get the peer address from the connection
		hostPort := strings.Split(peerAddr, ":")
		if len(hostPort) >= 1 {
			standardAddr := fmt.Sprintf("%s:12345", hostPort[0]) // Use standard port

			// Try to get the public key from our global map
			peerPublicKey, exists := GetPublicKey(peerID)

			if exists {
				// If we have a public key, update or add the contact now
				nickname := fmt.Sprintf("Peer-%s", peerID[:6])
				fmt.Printf("Adding peer %s to trusted contacts on verify\n", peerID)

				// Use direct method for reliability
				err := ForceWriteContact(peerID, standardAddr, peerPublicKey, nickname)
				if err != nil {
					fmt.Printf("Error directly writing contact: %v\n", err)
				} else {
					fmt.Printf("Successfully added peer %s to trusted contacts on verify\n", peerID)
				}
			}
		}

		// Update our contact entry if it exists
		if contactManager != nil && contactManager.IsTrusted(peerID) {
			contactManager.UpdateLastSeen(peerID)
			fmt.Printf("Updated trusted contact: %s\n", peerID)
		}
	} else if status == "rejected" {
		fmt.Printf("\nPeer %s has rejected the authentication request.\n", peerID)

	} else if status == "verifying" {
		// They're still deciding, nothing to do yet
		fmt.Printf("Peer %s is considering our authentication request\n", peerID)
	}
}

// Now modify your handleAuthTrust function to use this direct method

// handleAuthTrust handles trust status updates
func handleAuthTrust(conn net.Conn, addr string, payload string) error {
	// Parse the payload
	var data map[string]interface{}
	err := json.Unmarshal([]byte(payload), &data)
	if err != nil {
		return fmt.Errorf("error parsing TRUST message: %v", err)
	}

	peerID, ok := data["peer_id"].(string)
	if !ok {
		return fmt.Errorf("missing peer_id in TRUST message")
	}

	// Check if this is a trust status update or acknowledgment
	if trustedVal, ok := data["trusted"].(bool); ok {
		if trustedVal {
			fmt.Printf("\nPeer %s has added you as a trusted contact!\n", peerID)
		} else {
			fmt.Printf("\nPeer %s has removed you as a trusted contact.\n", peerID)
		}

		// Acknowledge the trust status update
		response := map[string]interface{}{
			"peer_id": authentication.PeerID,
			"status":  "acknowledged",
		}

		responseJSON, err := json.Marshal(response)
		if err != nil {
			return fmt.Errorf("error encoding acknowledgment: %v", err)
		}

		_, err = conn.Write([]byte(fmt.Sprintf("AUTH:TRUST:%s", responseJSON)))
		if err != nil {
			return fmt.Errorf("error sending acknowledgment: %v", err)
		}

		// If the peer trusts us, we should try to reciprocate
		if trustedVal {
			// Parse out host for address
			hostPort := strings.Split(addr, ":")
			if len(hostPort) >= 1 {
				peerAddr := fmt.Sprintf("%s:12345", hostPort[0]) // Use standard port

				// First try to get the public key from our global map
				peerPublicKey, exists := GetPublicKey(peerID)

				if !exists {
					// If not in our map, try to get it from pending verifications
					pendingMutex.RLock()
					for id, verif := range pendingVerifications {
						if id == peerID {
							peerPublicKey = verif.ContactData.PublicKey
							break
						}
					}
					pendingMutex.RUnlock()
				}

				if peerPublicKey != "" {
					fmt.Printf("Found public key for peer %s (length: %d)\n", peerID, len(peerPublicKey))

					// Use the direct method to save the contact
					nickname := fmt.Sprintf("Peer-%s", peerID[:6])
					err := ForceWriteContact(peerID, peerAddr, peerPublicKey, nickname)
					if err != nil {
						fmt.Printf("Error directly writing contact: %v\n", err)
					} else {
						fmt.Printf("Successfully added peer %s to trusted contacts via direct write\n", peerID)
					}

					// Also try the regular method
					if contactManager != nil {
						contactManager.AddTrustedContact(
							peerID,
							peerAddr,
							peerPublicKey,
							nickname,
						)
						contactManager.SaveContacts()
					}
				} else {
					fmt.Printf("Warning: No public key found for peer %s\n", peerID)

					// Emergency fallback - request authentication from the peer again
					fmt.Printf("Attempting to initiate authentication to get the public key...\n")
					success, err := InitiateAuthentication(peerAddr)
					if err != nil {
						fmt.Printf("Failed to initiate authentication: %v\n", err)
					} else if success {
						fmt.Printf("Successfully initiated authentication to retrieve public key\n")
					}
				}
			}
		}
	} else if status, ok := data["status"].(string); ok {
		// This is an acknowledgment of our trust message
		fmt.Printf("Received trust acknowledgment from peer %s: %s\n", peerID, status)
	} else {
		fmt.Printf("Missing trusted or status field in TRUST message from %s\n", peerID)
	}

	return nil
}

// Add this function to your auth_protocol.go file

// ForceWriteContact forcibly writes a contact to the trusted_contacts.json file
func ForceWriteContact(peerID, address, publicKey, nickname string) error {
	// Path to the trusted contacts file
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error getting home directory: %v", err)
	}

	contactsPath := filepath.Join(homeDir, ".p2p-share", "metadata", "trusted_contacts.json")
	fmt.Printf("Writing contact directly to file: %s\n", contactsPath)

	// Create contacts data structure
	var contacts map[string]TrustedContact

	// Try to read existing file
	data, err := os.ReadFile(contactsPath)
	if err == nil && len(data) > 0 {
		// File exists, try to parse it
		err = json.Unmarshal(data, &contacts)
		if err != nil {
			// If parsing fails, create a new map
			fmt.Printf("Error parsing existing contacts file: %v - Creating new map\n", err)
			contacts = make(map[string]TrustedContact)
		}
	} else {
		// File doesn't exist or is empty
		contacts = make(map[string]TrustedContact)
	}

	// Set the contact
	contacts[peerID] = TrustedContact{
		PeerID:     peerID,
		Address:    address,
		PublicKey:  publicKey,
		Nickname:   nickname,
		VerifiedAt: float64(time.Now().Unix()),
		LastSeen:   float64(time.Now().Unix()),
	}

	// Print debug info
	fmt.Printf("About to write %d contacts to file\n", len(contacts))
	for id, contact := range contacts {
		fmt.Printf("- Contact: %s at %s\n", id, contact.Address)
	}

	// Write the file
	newData, err := json.MarshalIndent(contacts, "", "  ")
	if err != nil {
		return fmt.Errorf("error serializing contacts: %v", err)
	}

	// Write to a temporary file first
	tempPath := contactsPath + ".tmp"
	err = os.WriteFile(tempPath, newData, 0644)
	if err != nil {
		return fmt.Errorf("error writing temporary contacts file: %v", err)
	}

	// Rename the temporary file to the actual file (atomic operation)
	err = os.Rename(tempPath, contactsPath)
	if err != nil {
		return fmt.Errorf("error renaming contacts file: %v", err)
	}

	fmt.Printf("Successfully wrote contacts file with %d entries\n", len(contacts))
	return nil
}
