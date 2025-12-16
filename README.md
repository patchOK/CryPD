# CryPD

CryPD is a lightweight command-line password manager written in Python. It allows you to securely store and retrieve credentials using strong local encryption, without relying on cloud services or external servers.

## Features
- Secure key derivation using PBKDF2-HMAC-SHA256
- Authenticated encryption with AES-GCM
- Encrypted local vault stored on disk
- Add, search, list, and delete credentials
- Simple and minimal CLI interface

## Requirements

- Python 3.6 or higher
- `cryptography` library

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/patchOK/CryPD.git
   ```
   
    Navigate to the project directory:
   ```bash
   cd CryPD
   ```

2. Install dependencies:
   ```bash
   pip install cryptography
   ```

## Usage
Run the application:
   ```bash
   python CryPD.py
   ```

You will be prompted to enter a master password, this password is used to derive the encryption key and decrypt the vault.

## Available Commands
Once started, the following actions are available:
- Search service: retrieve a stored password
- Add service: add a new service and password
- Delete service: remove a service from the vault
- Show services: list all stored service names
- Exit: close the application

## How It Works
CryPD uses PBKDF2-HMAC-SHA256 to derive a 256-bit key from the master password with a random salt. All data is encrypted using AES-GCM, providing confidentiality and integrity.

The vault file contains:
- Salt (16 bytes)
- Nonce (12 bytes)
- Encrypted data

The vault is decrypted only in memory after the correct master password is provided.

## Security Notes
- The vault is stored locally and never transmitted over the network
- Losing the master password means losing access to the vault
- Use a strong and unique master password
- Do not share or commit the vault file

## Disclaimer
This project is intended for educational and personal use. No guarantee is provided regarding suitability for production or high-security environments.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
