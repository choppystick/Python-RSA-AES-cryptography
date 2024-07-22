import os
import sys
import base64
from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Protocol.KDF import PBKDF2

# Global variable to store the derived key for the session
session_derived_key = None


def derive_session_key(key: str, salt: bytes) -> bytes:
    """
    Derives a session key using PBKDF2.

    :param key : The base key to derive from.
    :param salt : Salt for the key derivation.

    Returns:
        bytes: The derived session key.
    """
    global session_derived_key
    if session_derived_key is None:
        session_derived_key = PBKDF2(key, salt, 32, count=1000000, hmac_hash_module=SHA512)
    return session_derived_key


def clear_session_key() -> None:
    """
    Clears the global session key.
    """
    global session_derived_key
    session_derived_key = None


# This function generates the private and public keys
def generate_keys() -> tuple[bytes, bytes]:
    """
    Generates RSA public and private keys.

    Returns:
        tuple[bytes, bytes]: A tuple containing (public_key, private_key).
    """
    key = RSA.generate(2048)
    public_key = key.public_key().export_key()
    private_key = key.export_key()

    return public_key, private_key


def save_key(key: bytes, filename: str, password: str = None, is_name_key: bool = False, salt: bytes = None) -> None:
    """
    This function save the keys into a file for security. Can be encrypted with a passphrase.

    :param key: The key to save.
    :param filename: The filename to save the key to.
    :param password: Password to encrypt the key. Defaults to None. Optional.
    :param is_name_key: Whether this is a name key. Defaults to False. Optional.
    :param salt: Salt for name key encryption. Required if is_name_key is True. Optional Depending.
    """
    if is_name_key:

        with open(filename, "wb") as file:
            file.write(salt)
            file.write(key)

    else:
        if password:
            key = RSA.import_key(key).export_key(passphrase=password, pkcs=8,
                                                 protection="scryptAndAES128-CBC")
        with open(filename, "wb") as file:
            file.write(key)


def load_key(filename: str, password: str = None, is_name_key: bool = False):
    """
    Loads a key from a file.

    :param filename: The filename to load the key from.
    :param password: Password to decrypt the key. Defaults to None. Optional.
    :param is_name_key: Whether this is a name key. Defaults to False. Optional.

    """
    with open(filename, "rb") as file:
        if is_name_key:
            salt = file.read(16)
            key = file.read()
            return salt, key

        else:
            encoded_key = file.read()

    if password:
        key = RSA.import_key(encoded_key, passphrase=password)

    else:
        key = RSA.import_key(encoded_key)

    return key.export_key()


def encrypt_dir(directory: str, public_key: bytes, name_key: str, salt: bytes) -> str:
    """
    Encrypts an entire directory.
    :param directory: The location of where your files are located at.
    :param public_key: The public key generated using RSA.
    :param name_key : The private key used to encrypt the file names.
    :param salt: Salt for name encryption.

    WARNING:
    YOU MIGHT RISK RUINING YOUR ENTIRE SYSTEM AND CAUSING IRRECOVERABLE FILE LOSS.
    ONLY RUN THIS FUNCTION WHEN YOU ARE ABSOLUTELY SURE.
    """
    # Creates AES key
    aes_key = get_random_bytes(16)

    # Encrypt the AES key with RSA
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    for root, dirs, files in os.walk(directory, topdown=False):
        # Encrypt files
        for file_name in files:
            file_path = os.path.join(root, file_name)
            encrypt_file(file_path, aes_key, enc_aes_key, name_key, salt)

        # Encrypt directory names
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            name_change = encrypt_name(dir_name, name_key, salt)
            encrypted_path = os.path.join(root, name_change)
            os.rename(dir_path, encrypted_path)
            print(f"Folder {dir_path} has been encrypted and renamed to {encrypted_path}")

    # Encrypt root names
    root_name = os.path.basename(directory)
    print("root: " + root_name)
    root_change = encrypt_name(root_name, name_key, salt)
    encrypted_root = os.path.join(os.path.dirname(directory), root_change)
    os.rename(directory, encrypted_root)
    print(f"Root {directory} has been encrypted and renamed to {encrypted_root}")
    clear_session_key()
    return encrypted_root


def decrypt_dir(encrypted_dir_path: str, private_key: bytes, name_key: str, salt: bytes) -> str:
    """
    Decrypts an entire encrypted directory.

    :param encrypted_dir_path: The path of the encrypted directory.
    :param private_key: The private key for decryption.
    :param name_key: The key used to decrypt file and directory names.
    :param salt: Salt for name decryption.

    Returns:
        str: The path of the decrypted directory.
    """
    decrypted_root_name = decrypt_name(os.path.basename(encrypted_dir_path), name_key, salt)
    decrypted_root_path = os.path.join(os.path.dirname(encrypted_dir_path), decrypted_root_name)
    os.rename(encrypted_dir_path, decrypted_root_path)

    for root, dirs, files in os.walk(decrypted_root_path, topdown=False):
        for enc_file_name in files:
            enc_file_path = os.path.join(root, enc_file_name)
            decrypt_file(enc_file_path, private_key, name_key, salt)

        for enc_dir_name in dirs:
            enc_dir_path = os.path.join(root, enc_dir_name)
            decrypted_dir_name = decrypt_name(enc_dir_name, name_key, salt)
            decrypted_path = os.path.join(root, decrypted_dir_name)
            os.rename(enc_dir_path, decrypted_path)

    print(f"Directory '{decrypted_root_path}' has been decrypted.")
    clear_session_key()
    return decrypted_root_path


def encrypt_file(file_directory: str, aes_key: bytes, enc_aes_key: bytes, name_key: str, salt: bytes) -> None:
    """
    Encrypts a single file.

    :param file_directory: The path of the file to encrypt.
    :param aes_key: The AES key for file content encryption.
    :param enc_aes_key: The encrypted AES key.
    :param name_key: The key for encrypting the file name.
    :param salt: Salt for name encryption.

    WARNING:
    THIS IS THE ACTUAL ENCRYPTION FUNCTION. DO NOT USE THIS UNLESS YOU ARE ABSOLUTELY SURE THAT YOU KNOW WHAT YOU ARE
    DOING. THIS MAY POTENTIALLY LEAD TO IRRECOVERABLE FILE, DATA LOSS AND POTENTIALLY RUIN YOUR ENTIRE SYSTEM.
    """
    with open(file_directory, "rb") as files:
        data = files.read()

    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    encrypted_name = encrypt_name(os.path.basename(file_directory), name_key, salt)
    encrypted_path = os.path.join(os.path.dirname(file_directory), encrypted_name)

    with open(encrypted_path, "wb") as f:
        f.write(enc_aes_key)
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(ciphertext)

    os.remove(file_directory)
    print(f"File '{file_directory}' has been encrypted and renamed to '{encrypted_path}'")


def decrypt_file(encrypted_file_path: str, private_key: bytes, name_key: str, salt: bytes) -> None:
    """
    Decrypts a single encrypted file.

    :param encrypted_file_path: The path of the encrypted file.
    :param private_key: The private key for decryption.
    :param name_key: The key for decrypting the file name.
    :param salt: Salt for name decryption.
    """
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)

    with open(encrypted_file_path, "rb") as f:
        enc_aes_key = f.read(rsa_key.size_in_bytes())
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    aes_key = cipher_rsa.decrypt(enc_aes_key)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    decrypted_name = decrypt_name(os.path.basename(encrypted_file_path), name_key, salt)
    decrypted_file_path = os.path.join(os.path.dirname(encrypted_file_path), decrypted_name)

    with open(decrypted_file_path, "wb") as file:
        file.write(data)

    os.remove(encrypted_file_path)
    print(f"File {decrypted_file_path} has been decrypted.")


def encrypt_name(filename: str, key: str, salt: bytes) -> str:
    """
    Encrypts the name of a file or directory.

    :param salt: Salt for key derivation.
    :param filename: The name to encrypt.
    :param key: The key used for encryption.
    """
    salted_key = derive_session_key(key, salt)
    cipher = AES.new(salted_key, AES.MODE_GCM)
    data = filename.encode("utf-8")
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return base64.urlsafe_b64encode(cipher.nonce + tag + ciphertext).decode("utf-8")


def decrypt_name(encrypted_filename: str, key: str, salt: bytes) -> str:
    """
    Decrypts the name of a file or directory.

    :param salt: Salt for key derivation.
    :param encrypted_filename: The encrypted name to decrypt.
    :param key: The key used for decryption.
    """
    salted_key = derive_session_key(key, salt)
    data = base64.urlsafe_b64decode(encrypted_filename.encode("utf-8"))
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(salted_key, AES.MODE_GCM, nonce=nonce)

    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


def get_directory() -> str:
    """
    Prompts the user to enter a valid directory path.

    Returns:
        str: The validated directory path.
    """
    while True:
        directory = input("Enter the directory path to perform encryption/decryption: ").strip()
        if not directory:
            print("Error: Directory path cannot be empty.")
            continue

        if not os.path.exists(directory):
            print(f"Error: The directory '{directory}' does not exist.")
            continue

        return directory


if __name__ == "__main__":
    while True:
        try:
            choice = int(input("Encrypt(0) or Decrypt(1)? "))
            if choice not in [0, 1]:
                raise ValueError(" Please enter 0 for encryption or 1 for decryption.")
            break

        except ValueError as e:
            print(f"Invalid input: {e}")

    if choice == 0:
        public_key, private_key = generate_keys()  # key for the encryption/decryption
        name_key = base64.b64encode(get_random_bytes(32)).decode("utf-8")  # key for the name of the files
        salt = get_random_bytes(16)  # salt for hashing

        while True:
            try:
                choice = input("Do you want to secure your keys with a password? Enter only Y, y or N ,n: ").lower()
                if choice not in ["y", "n"]:
                    raise ValueError("Please enter only Y, y or N, n.")
                break

            except ValueError as e:
                print(f"Invalid input: {e}")

        if choice == "n":
            save_key(private_key, 'private_key.pem')
            save_key(public_key, 'public_key.pem')
            save_key(name_key.encode('utf-8'), 'name_key.pem', is_name_key=True, salt=salt)

        if choice == "y":
            password = input("Enter your password here. Remember this password: ")
            save_key(private_key, 'private_key.pem', password=password)
            save_key(public_key, 'public_key.pem', password=password)
            save_key(name_key.encode('utf-8'), 'name_key.pem', is_name_key=True, salt=salt)

        directory = get_directory()
        try:
            encrypted_dir = encrypt_dir(directory, public_key, name_key, salt)
            with open("dir.txt", "w") as file:
                file.write(encrypted_dir)
            print("Encryption completed.")

        except Exception as e:
            print(f"An exception occurred: {e}")

    if choice == 1:
        while True:
            try:
                choice = input("Did you secure your keys with a password? Enter only Y, y or N ,n: ").lower()
                if choice not in ["y", "n"]:
                    raise ValueError("Please enter only Y, y or N, n.")
                break

            except ValueError as e:
                print(f"Invalid input: {e}")

        if choice == "n":
            loaded_private_key = load_key('private_key.pem')
            salt, loaded_name_key = load_key('name_key.pem', is_name_key=True)

        if choice == "y":
            password = input("Enter your password here: ")
            try:
                loaded_private_key = load_key('private_key.pem', password=password)

            except ValueError as e:
                print(f"Invalid password.")
                sys.exit()

            salt, loaded_name_key = load_key('name_key.pem', is_name_key=True)

        with open("dir.txt", "r") as file:
            dirs = file.read()

        decrypt_dir(dirs, loaded_private_key, loaded_name_key, salt)
