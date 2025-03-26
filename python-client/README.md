# p2p-file-sharing/python-client/README.md

# Peer-to-Peer Secure File Sharing Application - Python Client

## Overview

This Python client is part of a peer-to-peer secure file sharing application that allows users to share files securely over a local network. The application supports mutual authentication, file requests, and ensures the confidentiality and integrity of files during transmission.

## Features

- Peer discovery using mDNS protocol.
- Mutual authentication of peers.
- File sharing capabilities with consent-based requests.
- Ability to list available files for sharing.
- Support for file retrieval from other peers if the original peer is offline.
- Key management for secure communication.
- Perfect forward secrecy to protect past communications.
- Secure storage of files on the local device.

## Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd p2p-file-sharing/python-client
   ```

2. **Install dependencies:**
   Make sure you have Python 3.x installed. Then, install the required packages using pip:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   You can start the Python client by executing:
   ```bash
   python src/main.py
   ```

## Directory Structure

```
python-client
├── src
│   ├── __init__.py
│   ├── main.py
│   ├── discovery
│   │   ├── __init__.py
│   │   └── mdns.py
│   ├── crypto
│   │   ├── __init__.py
│   │   ├── keys.py
│   │   └── encryption.py
│   ├── network
│   │   ├── __init__.py
│   │   ├── peer.py
│   │   └── protocol.py
│   └── storage
│       ├── __init__.py
│       └── filemanager.py
├── tests
│   ├── __init__.py
│   ├── test_crypto.py
│   ├── test_discovery.py
│   └── test_network.py
├── requirements.txt
└── README.md
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.