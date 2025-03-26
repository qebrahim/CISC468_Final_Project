# Go Client README.md

# Peer-to-Peer Secure File Sharing Application - Go Client

This README provides information about the Go client for the Peer-to-Peer Secure File Sharing Application. This application allows users to securely share files over a local network using a peer-to-peer architecture.

## Features

- **Peer Discovery**: Utilizes mDNS for discovering peers on the local network.
- **Mutual Authentication**: Ensures that peers can authenticate each other before sharing files.
- **File Sharing**: Allows users to send and request files securely.
- **File List Retrieval**: Users can request a list of available files from peers.
- **Offline File Access**: If a peer is offline, files can be requested from other peers who have previously downloaded them.
- **Key Management**: Supports migration to new keys if the old ones are compromised.
- **Confidentiality and Integrity**: Ensures that files are encrypted during transmission.
- **Perfect Forward Secrecy**: Protects past communications even if long-term keys are compromised.
- **Secure Storage**: Files are stored securely on the local device.

## Installation

1. Ensure you have Go installed on your machine. You can download it from [golang.org](https://golang.org/dl/).
2. Clone the repository:
   ```
   git clone <repository-url>
   ```
3. Navigate to the Go client directory:
   ```
   cd p2p-file-sharing/go-client
   ```
4. Install dependencies:
   ```
   go mod tidy
   ```

## Usage

To run the Go client, execute the following command in the terminal:

```
go run cmd/main.go
```

## Testing

To run the tests for the Go client, use the following command:

```
go test ./...
```

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.