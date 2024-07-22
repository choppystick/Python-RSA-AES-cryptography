# File Encryption with RSA-AES

This Python program provides a secure way to encrypt and decrypt files and directories using RSA and AES encryption algorithms. It's designed as a demonstration of cryptographical applications and for users who need to protect sensitive data on their local machine.

## Features

- Encrypt and decrypt entire directories
- Encrypt file contents and filenames separately
- Use of strong encryption algorithms (RSA and AES)
- Use of SHA512 hashing algorithms 

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Python 3.6 or higher
- PyCryptodome library

You can install PyCryptodome using pip:

```
pip install pycryptodome
```

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/choppystick/Python-RSA-AES-cryptography.git
   ```
2. Navigate to the project directory:
   ```
   cd Python-RSA-AES-cryptography
   ```

## Usage

### Encrypting a Directory

1. Run the script:
   ```
   python main.py
   ```
2. When prompted, enter `0` to choose encryption.
3. When further prompted, enter "y" to encrypt with password, and "n" to encrypt without password
4. Enter the desired password. (Warning: remember this password as there is no password recovery implementation)
5. Enter the full path of the directory you want to encrypt when prompted.
6. The program will generate encryption keys and save them in the current directory.
7. The program will encrypt the specified directory and all its contents.

### Decrypting a Directory

1. Run the script:
   ```
   python main.py
   ```
2. When prompted, enter `1` to choose decryption.
3. When further prompted, enter "y" if previously encrypted with password, and "n" if previously encrypted without password
3. Enter the password.
4. The program will use the saved keys to decrypt the previously encrypted directory.

## Safety Instructions

1. **Backup Your Data**: Before encrypting any files or directories, make sure you have a backup of your data in a secure location. This is crucial in case of any unexpected issues during the encryption process.

2. **Secure Your Keys**: The program generates and saves encryption keys. These keys are crucial for decryption. Store them securely and separately from the encrypted data. Consider using a password manager or a secure physical location.

3. **Remember Your Passwords**: If you choose to password-protect your keys, make sure you remember or securely store these passwords. Losing the password means losing access to your encrypted data.

4. **Test on Non-Critical Data First**: Before encrypting important data, test the program on non-critical files to ensure you understand how it works and that it functions correctly in your environment.

5. **Keep the Script Secure**: Ensure that only authorized users have access to the encryption script, as it contains the logic for both encryption and decryption.

6. **Use in a Secure Environment**: Run this program in a secure, private environment. Avoid using it on public or shared computers. 

7. **Verify Decryption**: After encrypting your files, verify that you can successfully decrypt them before deleting any original, unencrypted files.

## Warning

**PLEASE READ CAREFULLY**

This encryption program is a powerful tool that can permanently alter your files. Misuse or incorrect use can result in permanent data loss. Please consider the following warnings:

- **Data Loss Risk**: Incorrect use of this program, loss of encryption keys, or forgetting passwords can result in permanent, irrecoverable loss of your data.

- **No Recovery Mechanism**: This program does not include any built-in recovery mechanisms. If you lose your keys or passwords, there is no way to recover your encrypted data.

- **System Files**: Do not use this program to encrypt system files or directories. Doing so may render your system inoperable.

- **Legal Considerations**: Be aware of the legal implications of using encryption in your jurisdiction. Some countries have laws regulating the use of encryption. 

- **Misuses and Ethical Considerations**: This program is meant to be a demonstration of AES and RSA encryption. Do not attempt to use this program for any unethical purposes. Misuse of this program to alter files without permission or as a ransomware is highly illegal and will result in severe legal consequences.

By using this program, you acknowledge that you understand these risks and take full responsibility for any consequences resulting from its use. You also acknowledge that the misuse of this program is highly illegal and unethical.

## TO-DO
- Update readme.md
- Store keys in a server instead of on the local host


## Contributing

Contributions to this project are welcome. Please fork the repository and submit a pull request with your changes.

## License

[MIT License](https://opensource.org/licenses/MIT)

## Contact

If you have any questions or feedback, please open an issue in this repository.

