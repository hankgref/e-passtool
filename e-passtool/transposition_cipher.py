import sys

# File where passwords will be stored
PASSWORD_FILE = "stored_password.txt"
SECURE_PASSWORD_FILE = "secure_password.txt"
UNENCRYPTION_PASSWORD = "unencryption_password.txt"

# To store a password, run: "python3 transposition_cipher.py store (insert password here)"
# To print the stored password, run: "python3 transposition_cipher.py password"
# To encrypt the stored password, run: "python3 transposition_cipher.py encrypt (key value)"
# For help, run: "python3 transposition_cipher.py help"

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
    # Write the password identically to both files
    with open(PASSWORD_FILE, "w") as f:
        f.write(password)
    with open(SECURE_PASSWORD_FILE, "w") as g:
        g.write(password)
    print("Password stored successfully in both files.")

def store_unencryption_password(unencryption_password):
    with open(UNENCRYPTION_PASSWORD, "w") as h:
        h.write(unencryption_password)
    print("Unencryption password stored successfully.")
    print(f"{bcolors.FAIL}DO NOT LOSE THIS PASSCODE!{bcolors.ENDC}")

def print_password():
    try:
        with open(PASSWORD_FILE, "r") as f:
            stored_password = f.read()
        print("Stored Password:\n")
        print(stored_password)
    except FileNotFoundError:
        print("No password has been stored yet.")

def unencrypt_the_password():
    try:
        with open(SECURE_PASSWORD_FILE, "r") as g:
            stored_password = g.read()
        with open(PASSWORD_FILE, "w") as f:
            f.write(stored_password)
        print("Unencrypted Password:\n")
        print(stored_password)
    except FileNotFoundError:
        print("No password has been stored yet.")

def encrypt(text, key):
    # Create the encrypted text using a transposition cipher
    ciphertext = [''] * key
    for col in range(key):
        pointer = col
        while pointer < len(text):
            ciphertext[col] += text[pointer]
            pointer += key
    return ''.join(ciphertext)

def decrypt(text, key):
    # Create the decrypted text using a transposition cipher
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

def encrypt_stored_password():
    try:
        with open(PASSWORD_FILE, "r") as f:
            stored_password = f.read()
        if not stored_password:
            print("No password found to encrypt.")
            return
        key = int(input("Enter key value: "))
        encrypted_password = encrypt(stored_password, key)
        with open(PASSWORD_FILE, "w") as f:
            f.write(encrypted_password)
        print("Stored password encrypted successfully.")
    except FileNotFoundError:
        print(f"{bcolors.FAIL}ERROR: No password file found!{bcolors.ENDC}")
    except ValueError:
        print(f"{bcolors.FAIL}ERROR: Invalid key value.{bcolors.ENDC}")

def main():
    if len(sys.argv) < 2:
        print('')
        print('No argument found. For help, run "python3 transposition_cipher.py help"')
        return

    command = sys.argv[1]

    if command == "store":
        if len(sys.argv) > 2:
            password_to_store = " ".join(sys.argv[2:])
            store_password(password_to_store)
        else:
            print(f"{bcolors.WARNING}ERROR: No password found.{bcolors.ENDC}")
    
    elif command == "password":
        print_password()

    elif command == "unencrypt":
        unencrypt_the_password()
    
    elif command == "encrypt":
        encrypt_stored_password()

    elif command == "decryption_password":
        store_unencryption_password()

    elif command == "help":
        print('')
        print('To store a password, run: "python3 transposition_cipher.py store (insert password here)"')
        print('To print the stored password, run: "python3 transposition_cipher.py password"')
        print('To encrypt the stored password, run: "python3 transposition_cipher.py encrypt (insert key value here)"')
        print('To show the unencrypted password, run: "python3 transposition_cipher.py unencrypt"')
        print('')
        print("This program utilizes a transposition cipher for encryption.")
        print("It supports custom key values for encryption and decryption.")

if __name__ == "__main__":
    main()
