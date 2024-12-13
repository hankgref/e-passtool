import sys

# Files where passwords will be stored
PASSWORD_FILE_1 = "stored_password.txt"
SECURE_PASSWORD_FILE_1 = "secure_password.txt"
PASSWORD_FILE_2 = "stored_password_2.txt"
SECURE_PASSWORD_FILE_2 = "secure_password_2.txt"
PASSWORD_FILE_3 = "stored_password_3.txt"
SECURE_PASSWORD_FILE_3 = "secure_password_3.txt"

# Banned password list
DISALLOWED_PASSWORDS = ["password", "password1", "passwordpassword", "password123", "12345", "admin", "letmein", "qwerty"]

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
    if file_index == 2:
        password_file = PASSWORD_FILE_2
        secure_file = SECURE_PASSWORD_FILE_2
    elif file_index == 3:
        password_file = PASSWORD_FILE_3
        secure_file = SECURE_PASSWORD_FILE_3
    else:
        password_file = PASSWORD_FILE_1
        secure_file = SECURE_PASSWORD_FILE_1

    if password.lower() in DISALLOWED_PASSWORDS:
        print(f"{bcolors.FAIL}ERROR: Your password does not meet security standards. (It's bad.){bcolors.FAIL}")
        print(f"{bcolors.WARNING}Try something else.{bcolors.ENDC}")
        return

    # Write the password to both files
    with open(password_file, "w") as f:
        f.write(password)
    with open(secure_file, "w") as g:
        g.write(password)
    print(f"Password stored successfully in {password_file} and {secure_file}.")

def print_password(file_index=1):
    if file_index == 2:
        password_file = PASSWORD_FILE_2
    elif file_index == 3:
        password_file = PASSWORD_FILE_3
    else:
        password_file = PASSWORD_FILE_1

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
    elif file_index == 3:
        secure_file = SECURE_PASSWORD_FILE_3
        password_file = PASSWORD_FILE_3
    else:
        secure_file = SECURE_PASSWORD_FILE_1
        password_file = PASSWORD_FILE_1

    try:
        with open(secure_file, "r") as g:
            stored_password = g.read()
        with open(password_file, "w") as f:
            f.write(stored_password)
        print(f"Unencrypted Password from {secure_file}:\n{stored_password}")
    except FileNotFoundError:
        print(f"No password has been stored yet in {secure_file}.")

def encrypt(text, key):
    # Transposition cipher encryption
    ciphertext = [''] * key
    for col in range(key):
        pointer = col
        while pointer < len(text):
            ciphertext[col] += text[pointer]
            pointer += key
    return ''.join(ciphertext)

def decrypt(text, key):
    # Transposition cipher decryption
    num_cols = (len(text) + key - 1) // key
    num_rows = key
    num_shaded_boxes = (num_cols * num_rows) - len(text)
    plaintext = [''] * num_cols
    col, row = 0, 0
    for char in text:
        plaintext[col] += char
        col += 1
        if col == num_cols or (col == num_cols - 1 and row >= num_rows - num_shaded_boxes):
            col = 0
            row += 1
    return ''.join(plaintext)

def encrypt_stored_password(file_index=1):
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
            print(f"No password found in {password_file} to encrypt.")
            return

        key = int(input("Enter key value: "))
        encrypted_password = encrypt(stored_password, key)
        with open(password_file, "w") as f:
            f.write(encrypted_password)
        print(f"Stored password encrypted successfully in {password_file}.")
    except FileNotFoundError:
        print(f"{bcolors.FAIL}ERROR: No password file found!{bcolors.ENDC}")
    except ValueError:
        print(f"{bcolors.FAIL}ERROR: Invalid key value.{bcolors.ENDC}")

def main():
    if len(sys.argv) < 2:
        print(f'{bcolors.FAIL}No argument found. For help, run "python3 transposition_cipher.py help"{bcolors.ENDC}')
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
    elif command == "help":
        print(f"{bcolors.OKGREEN}Command usage:{bcolors.OKGREEN}")
        print('Store: "python3 transposition_cipher.py store (1|2|3) (password)"')
        print('Retrieve: "python3 transposition_cipher.py password (1|2|3)"')
        print('Encrypt: "python3 transposition_cipher.py encrypt (1|2|3)"')
        print('Unencrypt: "python3 transposition_cipher.py unencrypt (1|2|3)"')
        print(f"{bcolors.FAIL}{bcolors.ENDC}")
    else:
        print(f"{bcolors.FAIL}ERROR: Unknown command.{bcolors.ENDC}")

if __name__ == "__main__":
    main()
