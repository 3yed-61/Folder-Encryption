import os
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk as tkttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding as pad
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.fernet import Fernet
import webbrowser
import json
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import time
import tkinter.font

# Path to settings file
SETTINGS_FILE = "settings.json"

# Load settings from file
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as file:
            return json.load(file)
    return {
        "algorithm": "AES",
        "open_dir_after_op": True
    }

# Save settings to file
def save_settings():
    with open(SETTINGS_FILE, "w") as file:
        json.dump(settings, file)

# Global settings
settings = load_settings()

# Function to generate and save an encryption key
def generate_key(directory, folder_name, algorithm, password):
    if algorithm == "AES":
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = urlsafe_b64encode(kdf.derive(password.encode()))
        key_data = salt + key
    else:
        key = Fernet.generate_key()
        key_data = key

    key_path = os.path.join(directory, f"{folder_name}.key")
    with open(key_path, "wb") as key_file:
        key_file.write(key_data)
    return key_path

# Function to load an encryption key
def load_key(key_path, password):
    with open(key_path, "rb") as key_file:
        key_data = key_file.read()
    if settings["algorithm"] == "AES":
        salt = key_data[:16]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = urlsafe_b64encode(kdf.derive(password.encode()))
        return salt, key
    else:
        return key_data

# Function to encrypt a file with AES
def encrypt_file_aes(file_path, salt, key):
    with open(file_path, "rb") as file:
        data = file.read()

    padder = pad.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(urlsafe_b64decode(key)), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path, "wb") as file:
        file.write(iv + encrypted)

# Function to decrypt a file with AES
def decrypt_file_aes(file_path, salt, key):
    with open(file_path, "rb") as file:
        iv = file.read(16)
        encrypted = file.read()

    cipher = Cipher(algorithms.AES(urlsafe_b64decode(key)), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = pad.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    with open(file_path, "wb") as file:
        file.write(decrypted)

# Function to encrypt a file with Fernet
def encrypt_file_fernet(file_path, key):
    with open(file_path, "rb") as file:
        data = file.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    with open(file_path, "wb") as file:
        file.write(encrypted)

# Function to decrypt a file with Fernet
def decrypt_file_fernet(file_path, key):
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

# Function to update progress bar
def update_progress(progress, total):
    progress_bar['value'] = (progress / total) * 100
    root.update_idletasks()

# Function to reset progress bar
def reset_progress_bar():
    progress_bar['value'] = 0
    root.update_idletasks()

# Function to ask for a password and encrypt folder
def ask_password():
    password_window = tk.Toplevel(root)
    password_window.title("Enter Password")
    password_window.geometry("300x150")
    
    tk.Label(password_window, text="Enter a password (min 4 characters):", font=('Arial', 12)).pack(pady=10)
    
    password_var = tk.StringVar()
    password_entry = tk.Entry(password_window, textvariable=password_var, show="*", font=('Arial', 12))
    password_entry.pack(pady=5)
    password_entry.focus()  # Focus on the password entry box

    def on_submit():
        password = password_var.get()
        if len(password) < 4:
            messagebox.showerror("Error", "Password must be at least 4 characters long")
        else:
            password_window.destroy()
            encrypt_folder(password)
    
    submit_button = tk.Button(password_window, text="Submit", command=on_submit, font=('Arial', 10), bg="black", fg="white")
    submit_button.pack(pady=10)
    
    password_window.bind('<Return>', lambda event: on_submit())  # Bind the Enter key to the submit function

# Function to encrypt a folder in a thread
def encrypt_folder_thread(password, folder_path):
    try:
        reset_progress_bar()  # Reset the progress bar at the beginning
        start_time = time.time()
        folder_name = os.path.basename(folder_path)
        zip_path = zip_folder(folder_path)
        key_path = generate_key(os.path.dirname(folder_path), folder_name, settings["algorithm"], password)
        key_data = load_key(key_path, password)

        total_files = len(os.listdir(folder_path))  # Assuming we are counting files in the folder
        progress = 0

        if settings["algorithm"] == "AES":
            salt, key = key_data
            encrypt_file_aes(zip_path, salt, key)
        else:
            key = key_data
            encrypt_file_fernet(zip_path, key)

        progress += 1
        update_progress(progress, total_files)

        shutil.rmtree(folder_path)  # Delete the original folder after creating and encrypting the zip file
        end_time = time.time()
        elapsed_time = end_time - start_time
        log(f"Folder encrypted successfully.\nKey saved to {key_path}\n")
        log(f"Time taken: {elapsed_time // 60:.0f}m {elapsed_time % 60:.0f}s\n")
        time_process_label.config(text=f"{int(elapsed_time // 60):02d}:{int(elapsed_time % 60):02d}")
        if settings["open_dir_after_op"]:
            subprocess.Popen(f'explorer /select,{os.path.normpath(zip_path)}')  # Open directory containing the zip file
    except Exception as e:
        log_error(f"An error occurred during encryption: {e}")
        messagebox.showerror("Error", f"An error occurred: {e}")

# Function to decrypt a folder in a thread
def decrypt_folder_thread(password, zip_encrypted_path, key_path):
    try:
        reset_progress_bar()  # Reset the progress bar at the beginning
        start_time = time.time()
        key_data = load_key(key_path, password)

        total_files = 1  # Assuming we are decrypting a single zip file
        progress = 0

        if settings["algorithm"] == "AES":
            salt, key = key_data
            decrypt_file_aes(zip_encrypted_path, salt, key)
        else:
            key = key_data
            decrypt_file_fernet(zip_encrypted_path, key)

        progress += 1
        update_progress(progress, total_files)

        zip_decrypted_path = zip_encrypted_path.replace(".zip", "")
        shutil.unpack_archive(zip_encrypted_path, zip_decrypted_path)
        os.remove(zip_encrypted_path)  # Remove the zip file after extracting its contents
        os.remove(key_path)  # Remove the key file after decryption

        end_time = time.time()
        elapsed_time = end_time - start_time
        log("Folder decrypted and extracted successfully.\n")
        log(f"Time taken: {elapsed_time // 60:.0f}m {elapsed_time % 60:.0f}s\n")
        time_process_label.config(text=f"{int(elapsed_time // 60):02d}:{int(elapsed_time % 60):02d}")
        if settings["open_dir_after_op"]:
            subprocess.Popen(f'explorer /select,{os.path.normpath(zip_decrypted_path)}')  # Open directory containing the extracted files
    except Exception as e:
        log_error(f"An error occurred during decryption: {e}")
        messagebox.showerror("Error", f"An error occurred: {e}")


# Function to encrypt a folder
def encrypt_folder(password):
    folder_path = filedialog.askdirectory()
    if folder_path:
        threading.Thread(target=encrypt_folder_thread, args=(password, folder_path)).start()

# Function to decrypt a folder
def decrypt_folder():
    zip_encrypted_path = filedialog.askopenfilename(filetypes=[("Zip files", "*.zip")])
    if zip_encrypted_path:
        key_path = filedialog.askopenfilename(filetypes=[("Key files", "*.key")])
        if key_path:
            password_window = tk.Toplevel(root)
            password_window.title("Enter Password")
            password_window.geometry("300x150")
            
            tk.Label(password_window, text="Enter password:", font=('Arial', 12)).pack(pady=10)
            
            password_var = tk.StringVar()
            password_entry = tk.Entry(password_window, textvariable=password_var, show="*", font=('Arial', 12))
            password_entry.pack(pady=5)
            password_entry.focus()  # Focus on the password entry box

            def on_submit():
                password = password_var.get()
                password_window.destroy()
                threading.Thread(target=decrypt_folder_thread, args=(password, zip_encrypted_path, key_path)).start()
            
            submit_button = tk.Button(password_window, text="Submit", command=on_submit, font=('Arial', 10), bg="black", fg="white")
            submit_button.pack(pady=10)
            
            password_window.bind('<Return>', lambda event: on_submit())  # Bind the Enter key to the submit function

# Function to log messages
def log(message):
    log_text.configure(state='normal')
    log_text.insert(tk.END, message + "\n")
    log_text.configure(state='disabled')

# Function to log error messages
def log_error(message):
    log_text.configure(state='normal')
    log_text.insert(tk.END, "ERROR: " + message + "\n", "error")
    log_text.tag_config("error", foreground="red")
    log_text.configure(state='disabled')

# Function to show the settings window
def show_settings():
    settings_window = tk.Toplevel(root)
    settings_window.title("Settings")
    settings_window.geometry("300x230")
    settings_window.resizable(False, False)
    
    tk.Label(settings_window, text="Encryption Algorithm:", font=('cursive', 12)).pack(pady=10)

    algorithm_var = tk.StringVar(value=settings["algorithm"])
    aes_radio = tk.Radiobutton(settings_window, text="AES", variable=algorithm_var, value="AES", font=('Arial', 12))
    aes_radio.pack(pady=5)
    fernet_radio = tk.Radiobutton(settings_window, text="Fernet", variable=algorithm_var, value="Fernet", font=('Arial', 12))
    fernet_radio.pack(pady=5)

    open_dir_var = tk.BooleanVar(value=settings["open_dir_after_op"])
    open_dir_check = tk.Checkbutton(settings_window, text="Open directory after operation", variable=open_dir_var, font=('Arial', 12))
    open_dir_check.pack(pady=10)

    def save_settings_command():
        settings["algorithm"] = algorithm_var.get()
        settings["open_dir_after_op"] = open_dir_var.get()
        save_settings()
        settings_window.destroy()

    save_button = tk.Button(settings_window, text="Save", command=save_settings_command, font=('Arial', 10), bg="black", fg="white")
    save_button.pack(pady=10)

# Function to show developer information
def show_info():
    info_window = tk.Toplevel(root)
    info_window.title("Developer Info")
    info_window.geometry("200x120")
    info_window.resizable(False, False)
    
    tk.Label(info_window, text="Developer: 3λΞĐ", font=('Times', 12)).pack(pady=10)
    
    social_link = tk.Label(info_window, text="GitHub", font=('Times', 12), fg="blue", cursor="hand2")
    social_link.pack(pady=5)
    social_link.bind("<Button-1>", lambda e: webbrowser.open_new("https://github.com/3yed-61"))
    
    social_link = tk.Label(info_window, text="Twitter", font=('Times', 12), fg="blue", cursor="hand2")
    social_link.pack(pady=5)
    social_link.bind("<Button-1>", lambda e: webbrowser.open_new("https://twitter.com/_3yed_"))

# Initialize the main GUI window
root = tk.Tk() 
root.title("Folder Encryptor/Decryptor")
root.geometry("500x400")
root.resizable(False, False)
style = ttk.Style('darkly')

# Frame for the main operations
frame_main = ttk.Frame(root, padding=10)
frame_main.pack(fill=tk.BOTH, expand=True)

# Label for the application title
title_label = ttk.Label(frame_main, text="Folder Encryptor", font=('Times', 18, 'bold'))
title_label.pack(pady=10)

# Button to encrypt a folder
encrypt_button = ttk.Button(frame_main, text="Encrypt Folder", command=ask_password, bootstyle="primary")
encrypt_button.pack(pady=10)

# Button to decrypt a folder
decrypt_button = ttk.Button(frame_main, text="Decrypt Folder", command=decrypt_folder, bootstyle="success")
decrypt_button.pack(pady=10)

# Progress bar for the encryption/decryption process
progress_bar = ttk.Progressbar(frame_main, mode='determinate')
progress_bar.pack(fill=tk.X, padx=20, pady=10)

# Label for showing the time taken for the process
time_process_label = ttk.Label(frame_main, text="00:00", font=('Times', 12))
time_process_label.pack(pady=5)

# Frame for the log messages
frame_log = ttk.Frame(root, padding=10)
frame_log.pack(fill=tk.BOTH, expand=True)

# Text widget for showing log messages
log_text = scrolledtext.ScrolledText(frame_log, state='disabled', height=8)
log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Button to show the settings window
settings_button = ttk.Button(frame_main, text="Settings", command=show_settings, bootstyle="info")
settings_button.pack(pady=10)
settings_button.place(x=415, y=0)

# Info button for developer information
info_button = ttk.Button(root, text="i",  command=show_info, bootstyle="info")
info_button.place(x=10, y=10)

# Version label
version_label = ttk.Label(root, text="v 0.6", style='secondary.TLabel')
version_label.place(x=10, y=380)

# Run the GUI event loop
root.mainloop()
