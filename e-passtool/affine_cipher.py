import sys
import random
from math import gcd

# File where passwords will be stored
PASSWORD_FILE = "stored_password.txt"
SECURE_PASSWORD_FILE = "secure_password.txt"
UNENCRYPTION_PASSWORD = "unencryption_password.txt"

SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'

def main():
    if len(sys.argv) < 2:
        print('No argument found. For help, run "python3 affine_cipher.py help"')
        return

    command = sys.argv[1]

    # Handle the command
    if command == "store":
        if len(sys.argv) > 2:
            password_to_store = " ".join(sys.argv[2:])
            store_password(password_to_store)
        else:
            print("ERROR: No password found.")
    
    elif command == "password":
        print_password()

    elif command == "encrypt":
        encrypt_stored_password()

    elif command == "unencrypt":
        unencrypt_the_password()

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
        # The cipher is weak if key A is 1
        sys.exit('Cipher is weak if key A is 1. Choose a different key.')
        # The cipher is weak if key B is 0
    if keyB == 0 and mode == 'encrypt':
        # The cipher is weak if key B is 0
        sys.exit('Cipher is weak if key B is 0. Choose a different key.')
        # The cipher is weak if key A is 1
    if keyA < 0 or keyB < 0 or keyB > len(SYMBOLS) - 1:
        # Key A must be greater than 0 and Key B must be between 0 and len(SYMBOLS) - 1
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
            # Encrypt the symbol
            symbol_index = SYMBOLS.find(symbol)
            # Append the encrypted symbol
            ciphertext += SYMBOLS[(symbol_index * keyA + keyB) % len(SYMBOLS)]
        else:
            ciphertext += symbol  # Append the symbol without encrypting
    return ciphertext

def decrypt_message(key, message):
    """Decrypt the message using the Affine cipher."""
    keyA, keyB = get_key_parts(key)
    check_keys(keyA, keyB, 'decrypt')
    plaintext = ''
    # Find the modular inverse of keyA
    mod_inverse_of_keyA = mod_inverse(keyA, len(SYMBOLS))
    for symbol in message:
        # Decrypt the symbol
        if symbol in SYMBOLS:
            # Decrypt the symbol
            symbol_index = SYMBOLS.find(symbol)
            # Append the decrypted symbol
            plaintext += SYMBOLS[(symbol_index - keyB) * mod_inverse_of_keyA % len(SYMBOLS)]
        else:
            plaintext += symbol  # Append the symbol without decrypting
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

def store_password(password):
    """Store the password in plain text."""
    with open(PASSWORD_FILE, "w") as f:
        f.write(password)
    with open(SECURE_PASSWORD_FILE, "w") as g:
        g.write(password)
    print("Password stored successfully in both files.")

def encrypt_stored_password():
    """Encrypt the stored password using the Affine cipher."""
    try:
        with open(PASSWORD_FILE, "r") as f:
            stored_password = f.read()
        if not stored_password:
            print("No password found to encrypt.")
            return
        key = int(input("Enter a numeric key (e.g., 340, 2894, 462, 1273, 2145): "))
        encrypted_password = encrypt_message(key, stored_password)
        with open(PASSWORD_FILE, "w") as f:
            f.write(encrypted_password)
        print("Stored password encrypted successfully.")
    except FileNotFoundError:
        print("ERROR: No password file found.")
    except ValueError as e:
        print(f"ERROR: {str(e)}")

def unencrypt_the_password():
    """Decrypt the stored password using the Affine cipher."""
    try:
        with open(PASSWORD_FILE, "r") as f:
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

def print_password():
    """Print the stored password."""
    try:
        with open(PASSWORD_FILE, "r") as f:
            stored_password = f.read()
        print("Stored Password:")
        print(stored_password)
    except FileNotFoundError:
        print("No password has been stored yet.")

def print_help():
    """Print the help message."""
    print('To store a password, run: "python3 affine_cipher.py store (insert password here)"')
    print('To print the stored password, run: "python3 affine_cipher.py password"')
    print('To encrypt the stored password, run: "python3 affine_cipher.py encrypt"')
    print('To decrypt the stored password, run: "python3 affine_cipher.py unencrypt"')

if __name__ == "__main__":
    main()
