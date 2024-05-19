import os
import shutil
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet

# Function to generate and save an encryption key
def generate_key(directory):
    key = Fernet.generate_key()
    key_path = os.path.join(directory, "secret.key")
    with open(key_path, "wb") as key_file:
        key_file.write(key)
    return key_path

# Function to load an encryption key
def load_key(key_path):
    return open(key_path, "rb").read()

# Function to encrypt a file
def encrypt_file(file_path, key):
    with open(file_path, "rb") as file:
        data = file.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    with open(file_path, "wb") as file:
        file.write(encrypted)

# Function to decrypt a file
def decrypt_file(file_path, key):
    with open(file_path, "rb") as file:
        data = file.read()
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)
    with open(file_path, "wb") as file:
        file.write(decrypted)

# Function to zip a folder
def zip_folder(folder_path):
    zip_path = f"{folder_path}.zip"
    shutil.make_archive(folder_path, 'zip', folder_path)
    return zip_path

# Function to encrypt a folder
def encrypt_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        zip_path = zip_folder(folder_path)
        key_path = generate_key(os.path.dirname(folder_path))
        key = load_key(key_path)
        encrypt_file(zip_path, key)
        shutil.rmtree(folder_path)  # Delete the original folder after creating and encrypting the zip file
        notification_box.config(state=tk.NORMAL)
        notification_box.insert(tk.END, f"Folder encrypted successfully.\nKey saved to {key_path}\n")
        notification_box.config(state=tk.DISABLED)
        subprocess.Popen(f'explorer /select,{os.path.normpath(zip_path)}')  # Open directory containing the zip file

# Function to decrypt and extract a zip file
def decrypt_folder():
    zip_encrypted_path = filedialog.askopenfilename(title="Select Encrypted Zip File", filetypes=[("Encrypted Files", "*.zip")])
    if zip_encrypted_path:
        key_path = filedialog.askopenfilename(title="Select Key File", filetypes=[("Key Files", "*.key")])
        if key_path:
            key = load_key(key_path)
            decrypt_file(zip_encrypted_path, key)
            zip_decrypted_path = zip_encrypted_path.replace(".zip", "_decrypted.zip")
            os.rename(zip_encrypted_path, zip_decrypted_path)
            output_folder = zip_encrypted_path.replace(".zip", "")
            shutil.unpack_archive(zip_decrypted_path, output_folder, 'zip')
            os.remove(zip_decrypted_path)  # Delete the decrypted zip file for extra security
            os.remove(key_path)  # Delete the key file after decryption
            notification_box.config(state=tk.NORMAL)
            notification_box.insert(tk.END, "Folder decrypted successfully.\n")
            notification_box.config(state=tk.DISABLED)
            subprocess.Popen(f'explorer /select,{os.path.normpath(output_folder)}')  # Open directory containing the decrypted files

# Create GUI
root = tk.Tk()
root.title("Folder Encryption")
root.configure(bg='#6699cc')

frame = tk.Frame(root, bg='#6699cc')
frame.pack(padx=20, pady=20)

encrypt_button = tk.Button(frame, text="Encrypt Folder", command=encrypt_folder, bg='#3399ff', fg='white', font=('Arial', 12, 'bold'), relief='raised', bd=5)
encrypt_button.grid(row=0, column=0, padx=10, pady=10)

decrypt_button = tk.Button(frame, text="Decrypt Folder", command=decrypt_folder, bg='#33cc33', fg='white', font=('Arial', 12, 'bold'), relief='raised', bd=5)
decrypt_button.grid(row=0, column=1, padx=10, pady=10)

notification_box = tk.Text(frame, width=50, height=10, state=tk.DISABLED, bg='white', fg='black', font=('Arial', 10))
notification_box.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

# Personal Info Section
info_frame = tk.Frame(root, bg='#6699cc')
info_frame.pack(padx=20, pady=10)

info_label = tk.Label(info_frame, text="Developer: 3λΞĐ\nGitHub: github.com/3yed-61\nTwitter: @_3yed_", 
                      bg='#6699cc', fg='white', font=('Arial', 10, 'italic'))
info_label.pack()

root.mainloop()
