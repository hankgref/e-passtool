import sys
import pyperclip  # type: ignore # noqa: F401

# Files for password storage
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

def store_password(password, file_index=1):
    """Store the plaintext password in a file."""
    if password.lower() in DISALLOWED_PASSWORDS:
        print(f"{bcolors.FAIL}ERROR: Your password does not meet security standards.{bcolors.ENDC}")
        print(f"{bcolors.WARNING}Try something else.{bcolors.ENDC}")
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

    # Write the password identically to both files
    with open(password_file, "w") as f:
        f.write(password)
    with open(secure_file, "w") as g:
        g.write(password)
    print("Password stored successfully.")

def print_password(file_index=1):
    """Print the stored password from the plaintext file."""
    if file_index == 2:
        password_file = PASSWORD_FILE_2
    elif file_index == 3:
        password_file = PASSWORD_FILE_3
    else:
        password_file = PASSWORD_FILE_1

    try:
        with open(password_file, "r") as f:
            print(f"Stored Password from {password_file}:\n", f.read())
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

def encrypt_stored_password(file_index=1):
    """Encrypt the stored password using Vigenere cipher."""
    if file_index == 2:
        password_file = PASSWORD_FILE_2
    elif file_index == 3:
        password_file = PASSWORD_FILE_3
    else:
        password_file = PASSWORD_FILE_1

    try:
        with open(password_file, "r") as f:
            password = f.read()

        if not password:
            print("No password to encrypt.")
            return

        key = input("Enter encryption key (letters only!): ").strip()
        if not key.isalpha():
            print(f"{bcolors.FAIL}ERROR: Encryption key must be alphabetic!{bcolors.ENDC}")
            return

        encrypted_password = encrypt_message(key, password)

        with open(password_file, "w") as g:
            g.write(encrypted_password)

        print("Password encrypted successfully.")
    except FileNotFoundError:
        print(f"{bcolors.FAIL}No password found to encrypt!{bcolors.ENDC}")

def main():
    if len(sys.argv) < 2:
        print(f"{bcolors.WARNING}No argument found. Run with 'help' for usage.{bcolors.ENDC}")
        return

    command = sys.argv[1]
    file_index = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1

    if command == "store":
        if len(sys.argv) > 3:
            password = " ".join(sys.argv[3:])
            store_password(password, file_index)
        else:
            print(f"{bcolors.WARNING}ERROR: No password provided.{bcolors.ENDC}")

    elif command == "password":
        print_password(file_index)

    elif command == "encrypt":
        encrypt_stored_password(file_index)

    elif command == "help":
        print('To store a password, run: "python3 vigenere_cipher.py store (1|2|3) (insert password here)"')
        print('To print the stored password, run: "python3 vigenere_cipher.py password (1|2|3)"')
        print('To encrypt the stored password, run: "python3 vigenere_cipher.py encrypt (1|2|3)"')
        print('To decrypt the stored password, run: "python3 vigenere_cipher.py unencrypt (1|2|3)"')
        print(f"{bcolors.FAIL}Ensure the password is secure, avoiding disallowed common passwords.{bcolors.ENDC}")

if __name__ == "__main__":
    main()
