import secrets
import random

# Define character sets
uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
lowercase = "abcdefghijklmnopqrstuvwxyz"
digits = "1234567890"
special = "!@#$%^&*()_+=:?"
all_chars = uppercase + lowercase + digits + special

# Get password length with input validation
try:
    length_password = int(input("Enter the length of the password: "))
except ValueError:
    print("Invalid input. Please enter a number.")
    exit()

# Warn if the password is too short
if length_password < 8:
    print("Warning: It’s recommended to have at least 8 characters for a strong password.")

# Generate the password
if length_password >= 4:
    # Ensure one character from each category
    password_chars = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    # Fill the rest with random characters
    password_chars += [secrets.choice(all_chars) for _ in range(length_password - 4)]
    # Shuffle to avoid predictable order
    random.shuffle(password_chars)
    a = "".join(password_chars)
else:
    # For short passwords, select randomly from all characters
    a = "".join(secrets.choice(all_chars) for _ in range(length_password))

# Display the result
print(f"Your password is: {a}")