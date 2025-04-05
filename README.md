# p2p-file-sharing/README.md

# Peer-to-Peer Secure File Sharing Application

## Overview

This project implements a peer-to-peer secure file sharing application with two clients written in Python and Go. The clients are designed to communicate with each other using different cryptographic APIs while adhering to various security and functionality requirements.

## Features

- **Peer Discovery**: Utilizes mDNS for discovering peers on a local network.
- **Mutual Authentication**: Ensures that users can verify each other's identities.
- **File Sharing**: Allows peers to request and send files with consent.
- **File Listing**: Peers can request a list of available files without consent.
- **Offline File Retrieval**: Supports retrieving files from other peers if the original peer is offline.
- **Key Migration**: Users can migrate to a new key if their old one is compromised.
- **Confidentiality and Integrity**: Guarantees that files sent between users are secure.
- **Perfect Forward Secrecy**: Ensures that past communications remain secure even if long-term keys are compromised.
- **Secure Storage**: Files are stored securely on the local device.
- **Error Handling**: Displays appropriate messages for errors or security check failures.

## Setup Instructions

### Python Client

1. Navigate to the `python-client` directory.
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the Python client:
   ```
   python src/main.py
   ```

### Go Client

1. Navigate to the `go-client` directory.
2. Build the Go client:
   ```
   go build ./cmd
   ```
3. Run the Go client:
   ```
   ./cmd
   ```

## Testing

For python tests simply run the test file

For go tests run the application once regularly and connect to the python to establish keys then run the test suite using:
go test ./tests
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.