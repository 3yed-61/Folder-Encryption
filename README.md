# Folder Encryption Tool

This is a simple GUI application written in Python that allows you to encrypt and decrypt folders. The application uses the `cryptography` library for encryption and `tkinter` for the graphical user interface.

## Features


- **Encrypt Folder**: Compresses a selected folder into a zip file, encrypts the zip file, and deletes the original folder.
- **Decrypt Folder**: Decrypts a selected encrypted zip file, extracts its contents, and deletes the decrypted zip file and key file.

## Requirements

- Python 3.x
- `tkinter` (usually comes pre-installed with Python)
- `cryptography` library

## Installation

1. Clone the repository or download the source code.
2. Install the required Python library:
   ```bash
   pip install cryptography

## Usage
1. Run the script:
   ```bash
   python Folder Encryption.py

2. The GUI will open with two buttons: "Encrypt Folder" and "Decrypt Folder".

## Encrypt Folder

1. Click the "Encrypt Folder" button.
2. Select the folder you want to encrypt.
3. The application will create a zip file of the folder, encrypt it, delete the original folder, and display a success message with the location of the key file.

## Decrypt Folder

1. Click the "Decrypt Folder" button.
2. Select the encrypted zip file.
3. Select the key file that was generated during encryption.
4. The application will decrypt the zip file, extract its contents, delete the decrypted zip file and key file, and display a success message.

## Notes
Make sure to keep the key file safe as it is required for decryption.
The encrypted zip file and key file are saved in the same directory as the original folder.

