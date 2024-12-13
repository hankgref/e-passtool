import sys

# File where passwords will be stored
PASSWORD_FILE = "stored_password.txt"
# File where encrypted passwords will be stored
SECURE_PASSWORD_FILE = ".secure_password.txt"
# File where the password to unencrypt is stored
UNENCRYPTION_PASSWORD = ".unencryption_password.txt"
PASSWORD_FILE_2 = ".stored_password_2.txt"
SECURE_PASSWORD_FILE_2 = "secure_password_2.txt"
UNENCRYPTION_PASSWORD_2 = ".unencryption_password_2.txt"

# To store a password, run: "python3 ceasar_cipher.py store (insert password here)"
# To print the stored password, run: "python3 ceasar_cipher.py password"
# To encrypt the stored password, run: "python3 ceasar_cipher.py encrypt (shift value)"
# For help, run: "python3 ceasar_cipher.py help"

class bcolors:
    # Colors for the terminal
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
    if file_index == 2:
        password_file = PASSWORD_FILE_2
        secure_file = SECURE_PASSWORD_FILE_2
    else:
        password_file = PASSWORD_FILE
        secure_file = SECURE_PASSWORD_FILE
    # List of disallowed passwords
    disallowed_passwords = ["password", "password1", "passwordpassword", "password2", "password12", "password123", "password1234", "password12345", "password123456", "password1234567", "password12345678", "password123456789", "password1234567890", "password123456789", "password3", "passwordpassword", "Password", "PASSWORD", "Password1", "Password2", "Password12", "Password123", "Password1234", "Password12345", "Password123456", "Password1234567", "Password12345678", "Password123456789", "Password1234567890", "Password123456789", "Password3", "Passwordpassword", "passwordPassword", "passwordPASSWORD", "passwordPassword1", "passwordPassword2", "passwordPassword12", "passwordPassword123", "passwordPassword1234", "passwordPassword12345", "passwordPassword123456", "passwordPassword1234567", "passwordPassword12345678", "passwordPassword123456789", "passwordPassword1234567890", "passwordPassword123456789", "passwordPassword3", "passwordPasswordpassword", "passwordPasswordPassword", "passwordPasswordPASSWORD", "passwordPasswordPassword1", "passwordPasswordPassword2", "passwordPasswordPassword12", "passwordPasswordPassword123", "passwordPasswordPassword1234", "passwordPasswordPassword12345", "passwordPasswordPassword123456", "passwordPasswordPassword1234567", "passwordPasswordPassword12345678", "passwordPasswordPassword123456789", "passwordPasswordPassword1234567890", "passwordPasswordPassword123456789", "passwordPasswordPassword3", "passwordPasswordPasswordpassword", "passwordPasswordPasswordPassword", "passwordPasswordPasswordPASSWORD", "passwordPasswordPasswordPassword1", "passwordPasswordPasswordPassword2", "passwordPasswordPasswordPassword12", "passwordPasswordPasswordPassword123", "passwordPasswordPasswordPassword1234", "passwordPasswordPasswordPassword12345", "passwordPasswordPasswordPassword123456", "passwordPasswordPasswordPassword1234567", "passwordPasswordPasswordPassword12345678", "passwordPasswordPasswordPassword123456789", "passwordPasswordPasswordPassword1234567890", "passwordPasswordPasswordPassword123456789", "passwordPasswordPasswordPassword3", "passwordPasswordPasswordPasswordpassword", "passwordPasswordPasswordPasswordPassword", "passwordPasswordPasswordPasswordPASSWORD", "passwordPasswordPasswordPasswordPassword1", "passwordPasswordPasswordPasswordPassword2", "passwordPasswordPasswordPasswordPassword12", "passwordPasswordPasswordPasswordPassword123", "passwordPasswordPasswordPasswordPassword1234", "passwordPasswordPasswordPasswordPassword12345", "passwordPasswordPasswordPasswordPassword123456", "passwordPasswordPasswordPasswordPassword1234567", "passwordPasswordPasswordPasswordPassword12345678", "passwordPasswordPasswordPasswordPassword123456789", "passwordPassword"]

    if password.lower() in disallowed_passwords:
        print(f"{bcolors.FAIL}ERROR: Your password does not meet security standards. (It's bad.){bcolors.FAIL}")
        print(f"{bcolors.WARNING}Try something else.{bcolors.ENDC}")
        return
    
    # Write the password identically to both files
    with open(password_file, "w") as f:
        f.write(password)
    with open(secure_file, "w") as g:
        g.write(password)
    print(f"Password stored successfully in {password_file} and {secure_file}.")


def store_unencryption_password(unencryption_password, file_index=1):
    if file_index == 2:
        unencryption_file = UNENCRYPTION_PASSWORD_2
    else:
        unencryption_file = UNENCRYPTION_PASSWORD

    with open(unencryption_file, "w") as h:
        h.write(unencryption_password)
    print(f"Unencryption password stored successfully in {unencryption_file}.")
    print(f"{bcolors.FAIL}DO NOT LOSE THIS PASSCODE!{bcolors.ENDC}")

def print_password(file_index=1):
    if file_index == 2:
        password_file = PASSWORD_FILE_2
    else:
        password_file = PASSWORD_FILE

    try:
        with open(password_file, "r") as f:
            stored_password = f.read()
        print(f"Stored Password from {password_file}:\n{stored_password}")
    except FileNotFoundError:
        print(f"No password has been stored yet in {password_file}.")

def unencrypt_the_password(file_index=1):
    if file_index == 2:
        secure_file = SECURE_PASSWORD_FILE_2
        password_file = PASSWORD_FILE_2
    else:
        secure_file = SECURE_PASSWORD_FILE
        password_file = PASSWORD_FILE

    try:
        with open(secure_file, "r") as g:
            stored_password = g.read()
        with open(password_file, "w") as f:
            f.write(stored_password)
        print(f"Unencrypted Password from {secure_file}:\n{stored_password}")
    except FileNotFoundError:
        print(f"No password has been stored yet in {secure_file}.")

def encrypt(text, shift):
    result = ""
    # Traverse the plain text
    for char in text:
        # Encrypt uppercase characters
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        # Encrypt lowercase characters
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        # Non-alphabet characters remain unchanged
        else:
            result += char
    return result

def encrypt_stored_password(file_index=1):
    if file_index == 2:
        password_file = PASSWORD_FILE_2
    else:
        password_file = PASSWORD_FILE

    try:
        with open(password_file, "r") as f:
            stored_password = f.read()
        if not stored_password:
            print("No password found to encrypt.")
            return
        
        shift = int(input("Enter shift value: "))
        encrypted_password = encrypt(stored_password, shift)
        with open(password_file, "w") as f:
            f.write(encrypted_password)
        print(f"Stored password encrypted successfully in {password_file}.")
    except FileNotFoundError:
        print(f"{bcolors.FAIL}ERROR: No password file found!{bcolors.ENDC}")
    except ValueError:
        print(f"{bcolors.FAIL}ERROR: No shift value.{bcolors.ENDC}")

def main():
    if len(sys.argv) < 2:
        print('No argument found. For help, run "python3 ceasar_cipher.py help"')
        return

    command = sys.argv[1]
    file_index = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1

    if command == "store":
        if len(sys.argv) > 3:
            password_to_store = " ".join(sys.argv[3:])
            store_password(password_to_store, file_index)
        else:
            print(f"{bcolors.WARNING}ERROR: No password found.{bcolors.ENDC}")
    elif command == "password":
        print_password(file_index)
    elif command == "unencrypt":
        unencrypt_the_password(file_index)
    elif command == "encrypt":
        encrypt_stored_password(file_index)
    elif command == "decryption_password":
        if len(sys.argv) > 3:
            unencryption_password = sys.argv[3]
            store_unencryption_password(unencryption_password, file_index)
        else:
            print(f"{bcolors.WARNING}ERROR: No unencryption password provided.{bcolors.ENDC}")
    elif command == "help":
        print(f"{bcolors.OKGREEN}Command usage:{bcolors.OKGREEN}")
        print('Store: "python3 ceasar_cipher.py store (1|2) (password)"')
        print('Retrieve: "python3 ceasar_cipher.py password (1|2)"')
        print('Encrypt: "python3 ceasar_cipher.py encrypt (1|2)"')
        print('Unencrypt: "python3 ceasar_cipher.py unencrypt (1|2)"')
        print(f"{bcolors.FAIL}{bcolors.ENDC}")
    else:
        print(f"{bcolors.FAIL}ERROR: Unknown command.{bcolors.ENDC}")

if __name__ == "__main__":
    main()