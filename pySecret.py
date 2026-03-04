# Required external libraries:
#   $> pip install argon2-cffi
#   $> pip install pynacl

# ==============================
# Standard Library Imports
# ==============================
import os
import re
import threading
import time
import hashlib
import secrets
from datetime import datetime

# ==============================
# Cryptographic Imports
# ==============================
from argon2.low_level import hash_secret_raw, Type
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
)
from nacl.utils import random as nacl_random

# ==============================
# Global Runtime Variables
# ==============================
# Holds the derived secret in memory while active
globalSecret = None

# Thread responsible for automatic secret expiration
secret_timer_thread = None

# Cryptographic constants
SALT_LEN = 16  # Salt size in bytes
NONCE_LEN = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # Required nonce size

# ==============================
# Default Configuration Values
# These may be overridden by parameters.ini
# ==============================
SECRET_EXPIRATION_IN_SECONDS = 300
DEBUG_ON = False
RESULT_FILE_PATH = ""
RESULT_FILE_NAME = "data.dta"


# ==========================================================
# Utility Functions
# ==========================================================

def clear_screen():
    """
    Clears the terminal screen depending on the operating system.
    """
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    """
    Displays a separator and waits for user confirmation.
    """
    print("-" * 80)
    input("\nPress any key to continue...")


def read_parameters():
    """
    Reads optional configuration values from parameters.ini.
    Invalid values are ignored and defaults remain unchanged.
    """
    global SECRET_EXPIRATION_IN_SECONDS
    global DEBUG_ON
    global RESULT_FILE_NAME
    global RESULT_FILE_PATH

    if not os.path.exists("parameters.ini"):
        return

    try:
        with open("parameters.ini", "r") as f:
            lines = f.readlines()
    except Exception:
        return  # If file cannot be read, keep defaults

    for raw_line in lines:
        line = raw_line.strip()

        # Ignore empty lines, comments, or malformed entries
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if key == "SECRET_EXPIRATION_IN_SECONDS":
            try:
                SECRET_EXPIRATION_IN_SECONDS = int(value)
            except ValueError:
                pass  # Ignore invalid numeric value

        elif key == "DEBUG_ON":
            if value.lower() in ("true", "false"):
                DEBUG_ON = value.lower() == "true"

        elif key == "RESULT_FILE_PATH":
            if value:
                RESULT_FILE_PATH = value

        elif key == "RESULT_FILE_NAME":
            if value:
                RESULT_FILE_NAME = value


def secret_countdown(seconds):
    """
    Automatically clears the in-memory secret
    after the configured expiration time.
    """
    global globalSecret
    time.sleep(seconds)
    globalSecret = None


def normalize_string(param: str) -> str:
    """
    Deterministically maps an input string to a 6-character
    pseudo-random string using SHA-256 and a fixed charset.
    """
    charset = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "@!&*$"
    )

    digest = hashlib.sha256(param.encode("utf-8")).digest()

    result = []
    for i in range(6):
        index = digest[i] % len(charset)
        result.append(charset[index])

    return "".join(result)


def calculatePassword(quest1, quest2, quest3, quest4, quest5, date1, date2):
    """
    Normalizes all user inputs and combines them deterministically
    into a single byte sequence used as the master secret.
    """
    if DEBUG_ON:
        print("\n")
        print("=" * 60)
        print("\n--- Raw Input Summary ---\n")
        print("quest1:", quest1)
        print("quest2:", quest2)
        print("quest3:", quest3)
        print("quest4:", quest4)
        print("quest5:", quest5)
        print("date1:", date1)
        print("date2:", date2)        

    # Normalize all inputs
    quest1 = normalize_string(quest1)
    quest2 = normalize_string(quest2)
    quest3 = normalize_string(quest3)
    quest4 = normalize_string(quest4)
    quest5 = normalize_string(quest5)
    date1 = normalize_string(date1)
    date2 = normalize_string(date2)

    if DEBUG_ON:
        print("\n--- Normalized Values ---\n")
        print("quest1:", quest1)
        print("quest2:", quest2)
        print("quest3:", quest3)
        print("quest4:", quest4)
        print("quest5:", quest5)
        print("date1:", date1)
        print("date2:", date2)

    # Deterministically combine all parts (fixed order)
    combPassword = "".join([
        quest1,
        quest2,
        quest3,
        quest4,
        quest5,
        date1,
        date2
    ]).encode("utf-8")

    if DEBUG_ON:
        print("\n--- Combined password ---\n")
        print("Password:", combPassword)
        

    return combPassword


def generate_salt(length: int = 16) -> bytes:
    """
    Generates a cryptographically secure random salt.
    """
    return secrets.token_bytes(length)


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit encryption key from a password
    using Argon2id with defined security parameters.
    """
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    elif isinstance(password, bytes):
        password_bytes = password
    else:
        raise TypeError("Password must be str or bytes")

    return hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )


def encrypt_and_write(plaintext: str):
    """
    Encrypts the provided plaintext and overwrites the output file.
    A new salt and nonce are generated for every encryption.
    """
    salt = generate_salt()
    key = derive_key(globalSecret, salt)
    nonce = nacl_random(NONCE_LEN)

    if DEBUG_ON:
        print("\n")
        print("_" * 60)
        print(f"DEBUG - password     : {globalSecret}")
        print(f"DEBUG - salt         : {salt.hex()}")
        print(f"DEBUG - derived key  : {key.hex()}")
        print(f"DEBUG - nonce        : {nonce.hex()}")
        print("_" * 60)
        print("\n")

    ciphertext_with_tag = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext.encode("utf-8"),
        aad=None,
        nonce=nonce,
        key=key
    )    
        
    fullFilePath = getFullPath(RESULT_FILE_NAME, RESULT_FILE_PATH)
    with open(fullFilePath, "wb") as f:
        f.write(salt + nonce + ciphertext_with_tag)

def getFullPath(RESULT_FILE_NAME, RESULT_FILE_PATH):
    if RESULT_FILE_PATH == "":
        return RESULT_FILE_NAME
    else:
        # check if RESULT_FILE_PATH last character is '/' or '\'
        if RESULT_FILE_PATH[-1] in ['/', '\\']:
            return RESULT_FILE_PATH + RESULT_FILE_NAME
        else:
            # append a backslash '\' before the file name
            return RESULT_FILE_PATH + '\\' + RESULT_FILE_NAME

def decrypt_existing_file():
    """
    Decrypts the existing encrypted file.
    Returns plaintext as string or empty string if file does not exist.
    Raises exception if decryption fails.
    """

    fullFilePath = getFullPath(RESULT_FILE_NAME, RESULT_FILE_PATH)
    if not os.path.exists(fullFilePath):
        return ""

    with open(fullFilePath, "rb") as f:
        content = f.read()

    if len(content) < SALT_LEN + NONCE_LEN + 16:
        raise ValueError("Invalid file format.")

    salt = content[:SALT_LEN]
    nonce = content[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext_with_tag = content[SALT_LEN + NONCE_LEN:]

    key = derive_key(globalSecret, salt)

    plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext_with_tag,
        aad=None,
        nonce=nonce,
        key=key
    )

    return plaintext.decode("utf-8")


# ==========================================================
# Main Menu Actions
# ==========================================================

def set_password():
    """
    Collects user answers, derives a deterministic secret,
    and starts the automatic expiration timer.
    """
    global globalSecret, secret_timer_thread

    clear_screen()

    def get_text_input(question):
        while True:
            value = input(question + ": ").strip()
            if re.fullmatch(r"[a-zA-Z]{3,15}", value):
                return value.lower()
            else:
                print("Invalid entry. Only letters allowed (3–15 characters).")

    def get_date_input(question):
        while True:
            value = input(question + ": ").strip()

            if not value.isdigit() or len(value) != 8:
                print("Invalid format. Please enter exactly 8 digits in the format ddmmyyyy.")
                continue

            try:
                datetime.strptime(value, "%d%m%Y")
                return value
            except ValueError:
                print("Invalid date. Please enter a valid calendar date.")

    labels = [
        "Your favorite food",
        "Name of your first pet",        
        "Favorite musical instrument",
        "Favorite writer (FirstnameLastname)",
        "Favorite phrase (Initials)",
        "Mother's date of birth (ddmmyyyy)",
        "Date of first employment (ddmmyyyy)"
    ]

    LABEL_WIDTH = max(len(label) for label in labels) + 2

    quest1 = get_text_input(labels[0].ljust(LABEL_WIDTH))
    quest2 = get_text_input(labels[1].ljust(LABEL_WIDTH))
    quest3 = get_text_input(labels[2].ljust(LABEL_WIDTH))
    quest4 = get_text_input(labels[3].ljust(LABEL_WIDTH))
    quest5 = get_text_input(labels[4].ljust(LABEL_WIDTH))
    date1  = get_date_input(labels[5].ljust(LABEL_WIDTH))
    date2  = get_date_input(labels[6].ljust(LABEL_WIDTH))


    globalSecret = calculatePassword(
        quest1, quest2, quest3, quest4, quest5, date1, date2
    )

    seconds = SECRET_EXPIRATION_IN_SECONDS

    
    if DEBUG_ON:
        print("\nDebug Result:")
        print("\n--- Secret Expiration ---\n")
        print("Variable SECRET_EXPIRATION_IN_SECONDS:", seconds)
        print("\n")
        print("=" * 60)

    secret_timer_thread = threading.Thread(
        target=secret_countdown,
        args=(seconds,),
        daemon=True
    )
    secret_timer_thread.start()   
    print("\nResult:") 
    print("     - Password successfully generated")
    pause()


def read_file():
    """
    Decrypts and displays stored entries if a secret is active.
    """
    global globalSecret

    
    if globalSecret is None:
        clear_screen()
        print("\nResult:")
        print("     - WARNING: No secret set. Please run Option 1 first.")
        pause()
        return

    clear_screen()    
    try:
        plaintext = decrypt_existing_file()
        
        if not plaintext:
            print("\nResult:")
            print("     - File empty or not available")
        else:
            print("Decrypted text:\n")
            print("############################################################")
            print(plaintext)
            print("############################################################")

        pause()

    except Exception:
        print('\nResult:')
        print("     Error during decryption.")
        print("     Possible causes:")
        print("        - Incorrect password")
        print("        - The file has been modified")
        print("        - The file is corrupted")
        pause()


def write_file():
    """
    Encrypts new user input and prepends it
    to the existing encrypted log file.
    """
    global globalSecret

    if globalSecret is None:
        clear_screen()
        print("\nResult:")
        print("WARNING: No secret has been set. Please run Option 1 first.")
        pause()
        return

    clear_screen()

    new_text = input("Please enter text to encrypt: ").strip()
    
    if not new_text:
        print("\nResult:")
        print("No text was entered.")
        pause()
        return

    try:
        existing_text = decrypt_existing_file()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_entry = f"[{timestamp}] {new_text}"

        if existing_text:
            full_text = new_entry + "\n" + existing_text
        else:
            full_text = new_entry

        encrypt_and_write(full_text)

        print("\nResult:")
        print("     - Text successfully encrypted and saved.")
        pause()

    except Exception:
        print("\nResult:")
        print("     Error processing the file.")
        print("     Possible causes:")
        print("        - Incorrect password")
        print("        - The file has been modified")
        print("        - The file is corrupted")
        pause()


def write_details():
    """
    Displays currently active configuration values.
    """
    global SECRET_EXPIRATION_IN_SECONDS
    global DEBUG_ON
    global RESULT_FILE_NAME
    global RESULT_FILE_PATH
    fullFilePath = getFullPath(RESULT_FILE_NAME, RESULT_FILE_PATH)

    clear_screen()    
    print("Current configuration values (from parameters.ini or defaults):")
    print("     - SECRET_EXPIRATION_IN_SECONDS =", SECRET_EXPIRATION_IN_SECONDS)
    print("     - DEBUG_ON =", DEBUG_ON)
    print("     - RESULT_FILE_PATH =", RESULT_FILE_PATH)    
    print("     - RESULT_FILE_NAME =", RESULT_FILE_NAME)    
    print("     - Full File Path   =", fullFilePath)    
    pause()


def main_menu():
    """
    Displays the main application menu and
    routes user input to the selected action.
    """
    read_parameters()

    while True:
        clear_screen()
        print("===== MAIN MENU =====")
        print("1 - Set Password")
        print("2 - Read File")
        print("3 - Write File")
        print("8 - Print Parameters")
        print("9 - Exit")

        choice = input("\nSelect Option: ").strip()

        if choice == "1":
            set_password()
        elif choice == "2":
            read_file()
        elif choice == "3":
            write_file()
        elif choice == "8":
            write_details()
        elif choice == "9":
            clear_screen()
            print("Program Exited.")
            break
        else:
            clear_screen()
            print("Invalid Option.")
            time.sleep(1)


if __name__ == "__main__":
    main_menu()
