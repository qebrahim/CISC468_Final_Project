package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileHashInfo represents the hash information for a file
type FileHashInfo struct {
	Hash         string  `json:"hash"`
	Size         int64   `json:"size"`
	OriginPeer   string  `json:"origin_peer"`
	LastVerified float64 `json:"last_verified"`
}

// HashManager manages file hashes for verification
type HashManager struct {
	PeerID      string
	StoragePath string
	HashFile    string
	Hashes      map[string]FileHashInfo
}

// NewHashManager creates a new HashManager
func NewHashManager(peerID string) (*HashManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("error getting home directory: %v", err)
	}

	storagePath := filepath.Join(homeDir, ".p2p-share", "metadata")
	err = os.MkdirAll(storagePath, 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating metadata directory: %v", err)
	}

	hashFile := filepath.Join(storagePath, "file_hashes.json")

	manager := &HashManager{
		PeerID:      peerID,
		StoragePath: storagePath,
		HashFile:    hashFile,
		Hashes:      make(map[string]FileHashInfo),
	}

	// Load existing hashes if available
	err = manager.LoadHashes()
	if err != nil {
		fmt.Printf("Warning: Failed to load existing hashes: %v\n", err)
		// Continue with empty hash map
	}

	return manager, nil
}

// LoadHashes loads file hashes from storage
func (hm *HashManager) LoadHashes() error {
	// Check if file exists
	if _, err := os.Stat(hm.HashFile); os.IsNotExist(err) {
		// No hash file yet, initialize with empty map
		return hm.SaveHashes()
	}

	// Read hash file
	data, err := os.ReadFile(hm.HashFile)
	if err != nil {
		return fmt.Errorf("error reading hash file: %v", err)
	}

	// Parse JSON
	if len(data) > 0 {
		err = json.Unmarshal(data, &hm.Hashes)
		if err != nil {
			return fmt.Errorf("error parsing hash file: %v", err)
		}
	}

	return nil
}

// SaveHashes saves file hashes to storage
func (hm *HashManager) SaveHashes() error {
	data, err := json.MarshalIndent(hm.Hashes, "", "  ")
	if err != nil {
		return fmt.Errorf("error serializing hashes: %v", err)
	}

	err = os.WriteFile(hm.HashFile, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing hash file: %v", err)
	}

	return nil
}

// CalculateFileHash calculates SHA-256 hash of a file
func (hm *HashManager) CalculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("error calculating hash: %v", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// AddFileHash adds or updates a file hash entry
func (hm *HashManager) AddFileHash(filename, filePath string, originPeer string) (string, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return "", fmt.Errorf("error getting file info: %v", err)
	}

	fileHash, err := hm.CalculateFileHash(filePath)
	if err != nil {
		return "", err
	}

	if originPeer == "" {
		originPeer = hm.PeerID
	}

	basename := filepath.Base(filename)
	hm.Hashes[basename] = FileHashInfo{
		Hash:         fileHash,
		Size:         fileInfo.Size(),
		OriginPeer:   originPeer,
		LastVerified: float64(time.Now().Unix()),
	}

	err = hm.SaveHashes()
	if err != nil {
		fmt.Printf("Warning: Failed to save hashes: %v\n", err)
	}

	return fileHash, nil
}

// GetFileHash gets hash information for a file
func (hm *HashManager) GetFileHash(filename string) (FileHashInfo, bool) {
	basename := filepath.Base(filename)
	info, exists := hm.Hashes[basename]
	return info, exists
}

// VerifyFileHash verifies file integrity against expected hash or stored hash
func (hm *HashManager) VerifyFileHash(filePath, expectedHash string) (bool, error) {
	basename := filepath.Base(filePath)

	// If no expected hash provided, check if we have it stored
	if expectedHash == "" {
		if info, exists := hm.Hashes[basename]; exists {
			expectedHash = info.Hash
		}
	}

	if expectedHash == "" {
		return false, fmt.Errorf("no hash available for verification of %s", basename)
	}

	actualHash, err := hm.CalculateFileHash(filePath)
	if err != nil {
		return false, err
	}

	// Update last verification time if hash matches
	if actualHash == expectedHash {
		if info, exists := hm.Hashes[basename]; exists {
			info.LastVerified = float64(time.Now().Unix())
			hm.Hashes[basename] = info
			hm.SaveHashes()
		}
		return true, nil
	}

	return false, fmt.Errorf("hash verification failed for %s", basename)
}

// GetAllFileHashes gets all file hashes as a map
func (hm *HashManager) GetAllFileHashes() map[string]FileHashInfo {
	return hm.Hashes
}

// GetFileHashesAsString gets hash info for a list of files in the format needed for FILE_LIST command
func (hm *HashManager) GetFileHashesAsString(fileList []string) string {
	var result []string

	for _, filename := range fileList {
		basename := filepath.Base(filename)
		if info, exists := hm.Hashes[basename]; exists {
			result = append(result, fmt.Sprintf("%s,%s,%d", basename, info.Hash, info.Size))
		} else {
			// If we don't have hash info, just include the filename
			result = append(result, fmt.Sprintf("%s,,", basename))
		}
	}

	return strings.Join(result, ";")
}
