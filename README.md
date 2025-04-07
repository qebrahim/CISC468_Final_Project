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


## Commands

- **1. Shows connected peers
- **2. Requests file from a specified peer
- **3. Shares file to all connected peers
- **4. Lists all shared files betweent he 2 peers
- **5. Authenticates peer. This must be done before sharing/requesting any files.
- **6. Shows authenticated peers
- **7. Establishes a secure channel between peers. This is also done before secure file sharing
- **8. Can add files to view and or send
- **9. Key migration feature which changes keys and alerts connected peers
- **10. Allows client to access any secure files
- **11. Allows client to encrypt a local file so an attacker cannot steal the device and see it
- **12. Terminates the client 



## Setup Instructions


### Go Client

1. Navigate to the `go-client` directory. The go client should be run first.

   ```
2. Run the Go client:
   ```
   go run main.go
   ```

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

## Testing

For python tests simply run the test file

For go tests run the application once regularly and connect to the python to establish keys then run the test suite using:
```
go test ./tests
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.