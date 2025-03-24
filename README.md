# CLI Password Manager

A simple command-line password manager that securely stores, retrieves, and deletes passwords using encryption.

## Features

- Securely store passwords with encryption
- Retrieve saved passwords
- List all stored services
- Delete passwords
- Automatically generate strong passwords

## Requirements

- Python 3.7+
- `cryptography` library

## Installation

1. Clone the repository or download the script.
2. Install required dependencies:
   ```sh
   pip install cryptography
   ```

## Usage

Run the script with the following commands:

### Add a new password

```sh
python password_manager.py add <service> <length>
```

Example:

```sh
python password_manager.py add Gmail 16
```

### Retrieve a stored password

```sh
python password_manager.py get <service>
```

Example:

```sh
python password_manager.py get Gmail
```

### List all stored services

```sh
python password_manager.py list
```

### Delete a stored password

```sh
python password_manager.py delete <service>
```

Example:

```sh
python password_manager.py delete Gmail
```

## Security

- Uses a master password for encryption and decryption.
- Passwords are stored securely using AES encryption.
- A salt file (`salt.bin`) is used for key derivation to enhance security.

## Notes

- The first time you use the tool, you will be prompted to enter a master password. Use the same password for future access.
- If you forget the master password, you won't be able to recover stored passwords.

## License

This project is open-source and available under the MIT License.
