import argparse
import base64
import hashlib
import json
import os
import secrets
from getpass import getpass

from cryptography.fernet import Fernet


def derive_key(master_password: str, salt_file="salt.bin") -> tuple[bytes, bytes]:
    if os.path.exists(salt_file):
        with open(salt_file, "rb") as f:
            salt = f.read()
    else:
        salt = secrets.token_bytes(16)
        with open(salt_file, "wb") as f:
            f.write(salt)

    key = hashlib.pbkdf2_hmac("sha256", master_password.encode(), salt, 100000, 32)
    return base64.urlsafe_b64encode(key), salt


def save_passwords(data: dict, filename: str, fernet: Fernet):
    """Encrypts and saves password data to a file."""
    encrypted_data = fernet.encrypt(json.dumps(data).encode())
    with open(filename, "wb") as f:
        f.write(encrypted_data)


def load_passwords(filename: str, fernet: Fernet) -> dict:
    """Loads and decrypts password data from a file."""
    try:
        with open(filename, "rb") as f:
            encrypted_data = f.read()
        return json.loads(fernet.decrypt(encrypted_data).decode())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def generate_password(length: int) -> str:
    """Generates a secure random password."""
    alphabet = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+="
    )
    return "".join(secrets.choice(alphabet) for _ in range(length))


def setup_cli():
    """Sets up CLI argument parsing."""
    parser = argparse.ArgumentParser(description="CLI Password Manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_parser = subparsers.add_parser("add", help="Add a new password")
    add_parser.add_argument("service", help="Service name (e.g., Gmail)")
    add_parser.add_argument("length", type=int, help="Password length")

    get_parser = subparsers.add_parser("get", help="Retrieve a password")
    get_parser.add_argument("service", help="Service name")

    subparsers.add_parser("list", help="List all stored services")

    delete_parser = subparsers.add_parser("delete", help="Delete a password")
    delete_parser.add_argument("service", help="Service name")

    return parser.parse_args()


def main():
    args = setup_cli()
    master_password = getpass("Enter your master password: ")
    key, _ = derive_key(master_password)
    fernet = Fernet(key)
    passwords = load_passwords("passwords.json", fernet)

    if args.command == "add":
        password = generate_password(args.length)
        passwords[args.service] = password
        save_passwords(passwords, "passwords.json", fernet)
        print(f"Password for {args.service}: {password}")
    elif args.command == "get":
        print(
            f"Password for {args.service}: {passwords.get(args.service, 'Service not found.')}"
        )
    elif args.command == "list":
        print(
            "Stored services:",
            ", ".join(passwords.keys()) if passwords else "No services found.",
        )
    elif args.command == "delete":
        if args.service in passwords:
            del passwords[args.service]
            save_passwords(passwords, "passwords.json", fernet)
            print(f"Deleted password for {args.service}")
        else:
            print("Service not found.")


if __name__ == "__main__":
    main()
