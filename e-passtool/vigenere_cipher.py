import sys
import pyperclip  # type: ignore # noqa: F401

# Files for password storage
PASSWORD_FILE = "stored_password.txt"
SECURE_PASSWORD_FILE = "secure_password.txt"

# Vigenère Cipher constants
LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def store_password(password):
    """Store the plaintext password in a file."""
    with open(PASSWORD_FILE, "w") as f:
        f.write(password)
    print("Password stored successfully.")

def print_password():
    """Print the stored password from the plaintext file."""
    try:
        with open(PASSWORD_FILE, "r") as f:
            print("Stored Password:\n", f.read())
    except FileNotFoundError:
        print("No password has been stored yet.")

def encrypt_message(key, message):
    """Encrypt the message using the Vigenère cipher."""
    return translate_message(key, message, "encrypt")

def decrypt_message(key, message):
    """Decrypt the message using the Vigenère cipher."""
    return translate_message(key, message, "decrypt")

def translate_message(key, message, mode):
    """Translate the message with the Vigenère cipher."""
    translated = []
    key = key.upper()
    key_index = 0

    for symbol in message:
        num = LETTERS.find(symbol.upper())
        if num != -1:  # Symbol found in LETTERS
            if mode == "encrypt":
                num += LETTERS.find(key[key_index])
            elif mode == "decrypt":
                num -= LETTERS.find(key[key_index])

            num %= len(LETTERS)

            # Preserve case
            if symbol.isupper():
                translated.append(LETTERS[num])
            elif symbol.islower():
                translated.append(LETTERS[num].lower())

            key_index = (key_index + 1) % len(key)  # Move to the next key letter
        else:
            translated.append(symbol)  # Non-alphabet characters stay unchanged

    return ''.join(translated)

def encrypt_stored_password():
    """Encrypt the stored password using Vigenere cipher."""
    try:
        with open(PASSWORD_FILE, "r") as f:
            password = f.read()

        if not password:
            print("No password to encrypt.")
            return

        key = input("Enter encryption key (letters only!): ").strip()
        if not key.isalpha():
            print(f"{bcolors.FAIL}ERROR: Encryption key must be alphabetic!{bcolors.ENDC}")
            return

        encrypted_password = encrypt_message(key, password)

        with open(SECURE_PASSWORD_FILE, "w") as g:
            g.write(encrypted_password)

        print("Password encrypted successfully.")
    except FileNotFoundError:
        print(f"{bcolors.FAIL}No password found to encrypt!{bcolors.ENDC}")


def decrypt_stored_password():
    """Decrypt the stored password using Vigenère cipher."""
    try:
        with open(SECURE_PASSWORD_FILE, "r") as g:
            encrypted_password = g.read()

        key = input("Enter decryption key (letters only): ").strip()
        if not key.isalpha():
            print(f"{bcolors.FAIL}ERROR: Decryption key must be alphabetic!{bcolors.ENDC}")
            return

        decrypted_password = decrypt_message(key, encrypted_password)

        print("Decrypted Password:\n", decrypted_password)
    except FileNotFoundError:
        print(f"{bcolors.FAIL}No encrypted password found!{bcolors.ENDC}")


def main():
    if len(sys.argv) < 2:
        print(f"{bcolors.WARNING}No argument found. Run with 'help' for usage.{bcolors.ENDC}")
        return

    command = sys.argv[1]

    if command == "store":
        if len(sys.argv) > 2:
            password = " ".join(sys.argv[2:])
            store_password(password)
        else:
            print(f"{bcolors.WARNING}ERROR: No password provided.{bcolors.ENDC}")

    elif command == "password":
        print_password()

    elif command == "encrypt":
        encrypt_stored_password()

    elif command == "decrypt":
        decrypt_stored_password()

    elif command == "help":
        """Print the help message."""
        print('To store a password, run: "python3 vigenere_cipher.py store (insert password here)"')
        print('To print the stored password, run: "python3 vigenere_cipher.py password"')
        print('To encrypt the stored password, run: "python3 vigenere_cipher.py encrypt"')
        print('To decrypt the stored password, run: "python3 vigenere_cipher.py unencrypt"')

if __name__ == "__main__":
    main()
