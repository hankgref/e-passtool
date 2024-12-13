import sys
import random
from math import gcd

# Files where passwords will be stored
PASSWORD_FILE_1 = "stored_password_1.txt"
SECURE_PASSWORD_FILE_1 = "secure_password_1.txt"
PASSWORD_FILE_2 = "stored_password_2.txt"
SECURE_PASSWORD_FILE_2 = "secure_password_2.txt"
PASSWORD_FILE_3 = "stored_password_3.txt"
SECURE_PASSWORD_FILE_3 = "secure_password_3.txt"

# Disallowed passwords
DISALLOWED_PASSWORDS = [
    "password", "password1", "passwordpassword", "password2", "password12", 
    "password123", "password1234", "password12345", "password123456", "password1234567",
    "password12345678", "password123456789", "password1234567890", "123456", "12345", "abcde", 
    "letmein", "welcome", "qwerty", "123123", "monkey", "password1234", "password12345"
]

SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'

def main():
    if len(sys.argv) < 2:
        print('No argument found. For help, run "python3 affine_cipher.py help"')
        return

    command = sys.argv[1]
    file_index = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1

    # Handle the command
    if command == "store":
        if len(sys.argv) > 3:
            password_to_store = " ".join(sys.argv[3:])
            store_password(password_to_store, file_index)
        else:
            print("ERROR: No password found.")
    
    elif command == "password":
        print_password(file_index)

    elif command == "encrypt":
        encrypt_stored_password(file_index)

    elif command == "unencrypt":
        unencrypt_the_password(file_index)

    elif command == "help":
        print_help()

    else:
        print(f"Unknown command: {command}. For help, run 'python3 affine_cipher.py help'")

def get_key_parts(key):
    """Split the key into keyA and keyB components."""
    keyA = key // len(SYMBOLS)
    keyB = key % len(SYMBOLS)
    return keyA, keyB

def check_keys(keyA, keyB, mode):
    """Validate the keys for encryption/decryption."""
    if keyA == 1 and mode == 'encrypt':
        sys.exit('Cipher is weak if key A is 1. Choose a different key.')
    if keyB == 0 and mode == 'encrypt':
        sys.exit('Cipher is weak if key B is 0. Choose a different key.')
    if keyA < 0 or keyB < 0 or keyB > len(SYMBOLS) - 1:
        sys.exit(f"Key A must be greater than 0 and Key B must be between 0 and {len(SYMBOLS) - 1}.")
    if gcd(keyA, len(SYMBOLS)) != 1:
        sys.exit(f"Key A ({keyA}) and the symbol set size ({len(SYMBOLS)}) are not relatively prime. Choose a different key.")

def encrypt_message(key, message):
    """Encrypt the message using the Affine cipher."""
    keyA, keyB = get_key_parts(key)
    check_keys(keyA, keyB, 'encrypt')
    ciphertext = ''
    for symbol in message:
        if symbol in SYMBOLS:
            symbol_index = SYMBOLS.find(symbol)
            ciphertext += SYMBOLS[(symbol_index * keyA + keyB) % len(SYMBOLS)]
        else:
            ciphertext += symbol
    return ciphertext

def decrypt_message(key, message):
    """Decrypt the message using the Affine cipher."""
    keyA, keyB = get_key_parts(key)
    check_keys(keyA, keyB, 'decrypt')
    plaintext = ''
    mod_inverse_of_keyA = mod_inverse(keyA, len(SYMBOLS))
    for symbol in message:
        if symbol in SYMBOLS:
            symbol_index = SYMBOLS.find(symbol)
            plaintext += SYMBOLS[(symbol_index - keyB) * mod_inverse_of_keyA % len(SYMBOLS)]
        else:
            plaintext += symbol
    return plaintext

def mod_inverse(a, m):
    """Find the modular inverse of a with respect to m."""
    if gcd(a, m) != 1:
        raise ValueError("Key A and the size of the symbol set must be relatively prime.")
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        u1, u2, u3, v1, v2, v3 = v1, v2, v3, u1 - q * v1, u2 - q * v2, u3 - q * v3
    return u1 % m

def get_random_key():
    """Generate a random valid key."""
    while True:
        keyA = random.randint(2, len(SYMBOLS))
        keyB = random.randint(2, len(SYMBOLS))
        if gcd(keyA, len(SYMBOLS)) == 1:
            return keyA * len(SYMBOLS) + keyB

def store_password(password, file_index=1):
    """Store the password in plain text."""
    if password.lower() in DISALLOWED_PASSWORDS:
        print("ERROR: Your password does not meet security standards.")
        print("Try something else.")
        return

    if file_index == 2:
        password_file = PASSWORD_FILE_2
        secure_file = SECURE_PASSWORD_FILE_2
    elif file_index == 3:
        password_file = PASSWORD_FILE_3
        secure_file = SECURE_PASSWORD_FILE_3
    else:
        password_file = PASSWORD_FILE_1
        secure_file = SECURE_PASSWORD_FILE_1

    with open(password_file, "w") as f:
        f.write(password)
    with open(secure_file, "w") as g:
        g.write(password)
    print("Password stored successfully in both files.")

def encrypt_stored_password(file_index=1):
    """Encrypt the stored password using the Affine cipher."""
    if file_index == 2:
        password_file = PASSWORD_FILE_2
    elif file_index == 3:
        password_file = PASSWORD_FILE_3
    else:
        password_file = PASSWORD_FILE_1

    try:
        with open(password_file, "r") as f:
            stored_password = f.read()
        if not stored_password:
            print("No password found to encrypt.")
            return
        key = int(input("Enter a numeric key (e.g., 340, 2894, 462, 1273, 2145): "))
        encrypted_password = encrypt_message(key, stored_password)
        with open(password_file, "w") as f:
            f.write(encrypted_password)
        print("Stored password encrypted successfully.")
    except FileNotFoundError:
        print("ERROR: No password file found.")
    except ValueError as e:
        print(f"ERROR: {str(e)}")

def unencrypt_the_password(file_index=1):
    """Decrypt the stored password using the Affine cipher."""
    if file_index == 2:
        password_file = PASSWORD_FILE_2
    elif file_index == 3:
        password_file = PASSWORD_FILE_3
    else:
        password_file = PASSWORD_FILE_1

    try:
        with open(password_file, "r") as f:
            encrypted_password = f.read()
        if not encrypted_password:
            print("No encrypted password found.")
            return
        key = int(input("Enter the numeric key used for encryption: "))
        decrypted_password = decrypt_message(key, encrypted_password)
        print("Decrypted Password:")
        print(decrypted_password)
    except FileNotFoundError:
        print("ERROR: No password file found.")
    except ValueError as e:
        print(f"ERROR: {str(e)}")

def print_password(file_index=1):
    """Print the stored password."""
    if file_index == 2:
        password_file = PASSWORD_FILE_2
    elif file_index == 3:
        password_file = PASSWORD_FILE_3
    else:
        password_file = PASSWORD_FILE_1

    try:
        with open(password_file, "r") as f:
            stored_password = f.read()
        print(f"Stored Password from {password_file}:")
        print(stored_password)
    except FileNotFoundError:
        print("No password has been stored yet.")

def print_help():
    """Print the help message."""
    print('To store a password, run: "python3 affine_cipher.py store (1|2|3) (insert password here)"')
    print('To print the stored password, run: "python3 affine_cipher.py password (1|2|3)"')
    print('To encrypt the stored password, run: "python3 affine_cipher.py encrypt (1|2|3)"')
    print('To decrypt the stored password, run: "python3 affine_cipher.py unencrypt (1|2|3)"')
    print("Ensure the password is secure, avoiding disallowed common passwords.")

if __name__ == "__main__":
    main()
