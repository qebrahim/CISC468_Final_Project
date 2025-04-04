package network

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"p2p-file-sharing/go-client/internal/crypto"
	"path/filepath"
	"strings"
	"time"
)

// OfflineFileRequest represents a request to find a file from alternative peers
type OfflineFileRequest struct {
	FileName        string `json:"file_name"`
	OriginalPeerID  string `json:"original_peer_id"`
	RequesterPeerID string `json:"requester_peer_id"`
	ExpectedHash    string `json:"expected_hash,omitempty"`
	Timestamp       int64  `json:"timestamp"`
}

// OfflineFileResponse represents a response to an offline file request
type OfflineFileResponse struct {
	FileName     string `json:"file_name"`
	PeerID       string `json:"peer_id"`
	Hash         string `json:"hash,omitempty"`
	HasFile      bool   `json:"has_file"`
	CanShare     bool   `json:"can_share"`
	PeerAddress  string `json:"peer_address,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// RequestFileFromAlternative attempts to find and request a file from an alternative peer
// if the original peer is offline
func RequestFileFromAlternative(fileName string, originalPeerID string, requesterPeerID string, expectedHash string) (bool, string, error) {
	fmt.Printf("Looking for alternative sources for file: %s\n", fileName)
	fmt.Printf("Original peer %s appears to be offline\n", originalPeerID)

	// Get the local contact manager to find other peers
	contactManager, err := crypto.GetContactManager()
	if err != nil {
		return false, "", fmt.Errorf("error getting contact manager: %v", err)
	}

	// Get all trusted contacts
	contacts := contactManager.GetAllTrustedContacts()
	if len(contacts) == 0 {
		return false, "", fmt.Errorf("no trusted contacts available to check for the file")
	}

	// Create the offline file request
	request := OfflineFileRequest{
		FileName:        fileName,
		OriginalPeerID:  originalPeerID,
		RequesterPeerID: requesterPeerID,
		ExpectedHash:    expectedHash,
		Timestamp:       time.Now().Unix(),
	}

	// Convert request to JSON
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return false, "", fmt.Errorf("error encoding offline file request: %v", err)
	}

	// Query all trusted contacts to find alternatives
	var alternativePeers []OfflineFileResponse
	for peerID, contact := range contacts {
		// Skip the original peer which we know is offline
		if peerID == originalPeerID {
			continue
		}

		// Skip self
		if peerID == requesterPeerID {
			continue
		}

		// Try to connect to this peer
		addr := contact.Address
		hostPort := strings.Split(addr, ":")
		if len(hostPort) != 2 {
			fmt.Printf("Invalid address format for peer %s: %s\n", peerID, addr)
			continue
		}

		fmt.Printf("Checking peer %s at %s for file: %s\n", peerID, addr, fileName)

		// Connect to the peer with timeout
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			fmt.Printf("Peer %s is not available: %v\n", peerID, err)
			continue
		}

		// Send offline file request
		_, err = conn.Write([]byte(fmt.Sprintf("OFFLINE_FILE_REQUEST:%s", requestJSON)))
		if err != nil {
			fmt.Printf("Error sending request to peer %s: %v\n", peerID, err)
			conn.Close()
			continue
		}

		// Set read deadline
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))

		// Read response
		buffer := make([]byte, 4096)
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Printf("Error reading response from peer %s: %v\n", peerID, err)
			conn.Close()
			continue
		}

		// Reset deadline
		conn.SetReadDeadline(time.Time{})

		// Parse response
		response := string(buffer[:n])
		if !strings.HasPrefix(response, "OFFLINE_FILE_RESPONSE:") {
			fmt.Printf("Invalid response from peer %s: %s\n", peerID, response)
			conn.Close()
			continue
		}

		// Extract response JSON
		responseJSON := strings.TrimPrefix(response, "OFFLINE_FILE_RESPONSE:")
		var offlineResponse OfflineFileResponse
		err = json.Unmarshal([]byte(responseJSON), &offlineResponse)
		if err != nil {
			fmt.Printf("Error parsing response from peer %s: %v\n", peerID, err)
			conn.Close()
			continue
		}

		// Check if the peer has the file
		if offlineResponse.HasFile && offlineResponse.CanShare {
			fmt.Printf("Peer %s has the file and is willing to share\n", peerID)
			alternativePeers = append(alternativePeers, offlineResponse)
		} else if offlineResponse.HasFile {
			fmt.Printf("Peer %s has the file but cannot share at this time\n", peerID)
		} else {
			fmt.Printf("Peer %s does not have the file\n", peerID)
		}

		conn.Close()
	}

	// Check if we found any alternative sources
	if len(alternativePeers) == 0 {
		return false, "", fmt.Errorf("no alternative sources found for file %s", fileName)
	}

	// Select the first available alternative (could be improved with more sophisticated selection)
	selectedPeer := alternativePeers[0]
	fmt.Printf("Selected peer %s as alternative source for file %s\n", selectedPeer.PeerID, fileName)

	// Request the file from the selected peer
	success, err := requestFileFromPeer(selectedPeer.PeerAddress, fileName, expectedHash)
	if err != nil {
		return false, "", fmt.Errorf("error requesting file from alternative peer: %v", err)
	}

	if success {
		return true, selectedPeer.PeerID, nil
	}

	return false, "", fmt.Errorf("failed to retrieve file from alternative peer")
}

// requestFileFromPeer requests a file from a specific peer with expected hash verification
func requestFileFromPeer(peerAddr, fileName, expectedHash string) (bool, error) {
	// Parse address
	hostPort := strings.Split(peerAddr, ":")
	if len(hostPort) != 2 {
		return false, fmt.Errorf("invalid address format: %s", peerAddr)
	}

	host := hostPort[0]
	port := hostPort[1]

	fmt.Printf("Requesting file '%s' from alternative peer %s:%s\n", fileName, host, port)

	// Create a new connection for the file request
	conn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false, fmt.Errorf("failed to connect to alternative peer: %v", err)
	}
	defer conn.Close()

	// Send file request
	requestMsg := fmt.Sprintf("REQUEST_FILE:%s", fileName)
	_, err = conn.Write([]byte(requestMsg))
	if err != nil {
		return false, fmt.Errorf("failed to send file request: %v", err)
	}

	// Set response timeout
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read response header
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return false, fmt.Errorf("error reading response: %v", err)
	}

	// Reset deadline for subsequent reads
	conn.SetReadDeadline(time.Time{})

	// Parse response
	response := string(buffer[:n])
	if strings.HasPrefix(response, "ERR") {
		return false, fmt.Errorf("error from peer: %s", response)
	}

	// Check for file data header
	if !strings.HasPrefix(response, "FILE_DATA:") {
		return false, fmt.Errorf("unexpected response: %s", response)
	}

	// Parse file header
	parts := strings.Split(response, ":")
	if len(parts) < 3 {
		return false, fmt.Errorf("invalid file header format")
	}

	receivedFileName := parts[1]
	fileSizeStr := parts[2]
	fileSize := 0
	fmt.Sscanf(fileSizeStr, "%d", &fileSize)

	// Check for hash in header
	receivedHash := ""
	if len(parts) > 3 {
		receivedHash = parts[3]
	}

	// If we have an expected hash, compare with received hash
	if expectedHash != "" && receivedHash != "" && expectedHash != receivedHash {
		return false, fmt.Errorf("file hash mismatch: expected %s, got %s", expectedHash, receivedHash)
	}

	fmt.Printf("Receiving file %s (%d bytes) from alternative peer\n", receivedFileName, fileSize)

	// Create output directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false, fmt.Errorf("error getting home directory: %v", err)
	}

	outputDir := filepath.Join(homeDir, ".p2p-share", "shared")
	err = os.MkdirAll(outputDir, 0755)
	if err != nil {
		return false, fmt.Errorf("error creating output directory: %v", err)
	}

	outputPath := filepath.Join(outputDir, receivedFileName)
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return false, fmt.Errorf("error creating output file: %v", err)
	}
	defer outputFile.Close()

	// Calculate header length to determine if we already have some file data
	headerLength := len("FILE_DATA:") + len(receivedFileName) + 1 + len(fileSizeStr) + 1
	if receivedHash != "" {
		headerLength += len(receivedHash) + 1
	}

	// Write any data already received after the header
	if n > headerLength {
		_, err = outputFile.Write(buffer[headerLength:n])
		if err != nil {
			return false, fmt.Errorf("error writing to output file: %v", err)
		}
	}

	// Start hash calculation if hash verification is needed
	var hashCalculator *crypto.HashCalculator
	if expectedHash != "" {
		hashCalculator = crypto.NewHashCalculator()
		if n > headerLength {
			hashCalculator.Update(buffer[headerLength:n])
		}
	}

	// Download the rest of the file
	bytesReceived := n - headerLength
	if bytesReceived < 0 {
		bytesReceived = 0
	}

	for bytesReceived < fileSize {
		n, err := conn.Read(buffer)
		if err != nil && err != io.EOF {
			return false, fmt.Errorf("error reading file data: %v", err)
		}

		if n == 0 {
			break
		}

		_, err = outputFile.Write(buffer[:n])
		if err != nil {
			return false, fmt.Errorf("error writing to output file: %v", err)
		}

		if hashCalculator != nil {
			hashCalculator.Update(buffer[:n])
		}

		bytesReceived += n

		// Display progress
		percent := float64(bytesReceived) / float64(fileSize) * 100
		fmt.Printf("Download progress: %.1f%%\r", percent)
	}

	fmt.Println() // New line after progress display

	// If we didn't get the full file, warn the user
	if bytesReceived < fileSize {
		fmt.Printf("Warning: received only %d of %d bytes\n", bytesReceived, fileSize)
	}

	// Verify hash if needed
	if expectedHash != "" && hashCalculator != nil {
		calculatedHash := hashCalculator.Finalize()
		if calculatedHash != expectedHash {
			os.Remove(outputPath) // Delete corrupt file
			return false, fmt.Errorf("file hash mismatch after download: expected %s, got %s", expectedHash, calculatedHash)
		}
		fmt.Printf("File hash verified successfully: %s\n", calculatedHash)
	}

	fmt.Printf("File downloaded successfully to %s\n", outputPath)
	return true, nil
}

// HandleOfflineFileRequest processes a request for a file when the original owner is offline
func HandleOfflineFileRequest(conn net.Conn, requestJSON string) {
	var request OfflineFileRequest
	err := json.Unmarshal([]byte(requestJSON), &request)
	if err != nil {
		errorResponse := OfflineFileResponse{
			HasFile:      false,
			CanShare:     false,
			ErrorMessage: "Invalid request format",
		}
		sendOfflineFileResponse(conn, errorResponse)
		return
	}

	fmt.Printf("\nReceived offline file request for: %s (originally from peer %s)\n",
		request.FileName, request.OriginalPeerID)

	// Check if we have the file in our shared directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		errorResponse := OfflineFileResponse{
			HasFile:      false,
			CanShare:     false,
			ErrorMessage: "Error accessing local storage",
		}
		sendOfflineFileResponse(conn, errorResponse)
		return
	}

	sharedDir := filepath.Join(homeDir, ".p2p-share", "shared")
	filePath := filepath.Join(sharedDir, request.FileName)

	hasFile := false
	fileHash := ""

	// Check if file exists
	if _, err := os.Stat(filePath); err == nil {
		hasFile = true

		// Calculate file hash for verification
		if request.ExpectedHash != "" {
			hash, err := calculateFileHash(filePath)
			if err == nil {
				fileHash = hash

				// If hash doesn't match, we don't really have the right file
				if hash != request.ExpectedHash {
					fmt.Printf("File hash mismatch: expected %s, got %s\n",
						request.ExpectedHash, hash)
					hasFile = false
				}
			}
		}
	}

	if !hasFile {
		response := OfflineFileResponse{
			FileName: request.FileName,
			PeerID:   crypto.GetPeerID(),
			HasFile:  false,
			CanShare: false,
		}
		sendOfflineFileResponse(conn, response)
		return
	}

	// Ask user for consent to share the file
	fmt.Printf("Peer %s is requesting file '%s' (originally from %s)\n",
		request.RequesterPeerID, request.FileName, request.OriginalPeerID)
	fmt.Print("Do you want to share this file? (y/n): ")

	var answer string
	fmt.Scanln(&answer)

	canShare := strings.ToLower(answer) == "y"

	// Get our own address for the response
	peerAddr := ""
	if canShare {
		// Use default port for simplicity
		hostPort := strings.Split(conn.LocalAddr().String(), ":")
		if len(hostPort) >= 1 {
			peerAddr = fmt.Sprintf("%s:12345", hostPort[0])
		}
	}

	// Send response
	response := OfflineFileResponse{
		FileName:    request.FileName,
		PeerID:      crypto.GetPeerID(),
		Hash:        fileHash,
		HasFile:     true,
		CanShare:    canShare,
		PeerAddress: peerAddr,
	}

	sendOfflineFileResponse(conn, response)
	fmt.Printf("Responded to offline file request: can share = %v\n", canShare)
}

// sendOfflineFileResponse sends an offline file response to the requester
func sendOfflineFileResponse(conn net.Conn, response OfflineFileResponse) {
	responseJSON, err := json.Marshal(response)
	if err != nil {
		fmt.Printf("Error encoding offline file response: %v\n", err)
		return
	}

	_, err = conn.Write([]byte(fmt.Sprintf("OFFLINE_FILE_RESPONSE:%s", responseJSON)))
	if err != nil {
		fmt.Printf("Error sending offline file response: %v\n", err)
	}
}

// calculateFileHash calculates the SHA-256 hash of a file
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	hashBytes := hash.Sum(nil)
	hashString := fmt.Sprintf("%x", hashBytes)
	return hashString, nil
}

// HashCalculator helps calculate incremental hash of a file during download
// HashCalculator helps calculate incremental hash of a file during download
