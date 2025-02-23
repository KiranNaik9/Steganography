# steganography_decryption.py

import cv2
import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def reveal_message(image_path, password):
    """Reveals a hidden message from an image after password verification."""
    try:
        img = cv2.imread(image_path)
        if img is None:
            raise FileNotFoundError(f"Image not found at {image_path}")

        binary_message = ""
        for i in range(img.shape[0]):
            for j in range(img.shape[1]):
                for k in range(3):
                    binary_message += str(img[i, j, k] & 1)

        message_bytes = [binary_message[i:i + 8] for i in range(0, len(binary_message), 8)]
        decoded_message = ""
        for byte in message_bytes:
            if byte == "":
                break
            decoded_message += chr(int(byte, 2))
            if decoded_message.endswith("#####"):
                full_message = decoded_message[:-5]
                hashed_stored_password, actual_message = full_message.split("::", 1)
                if hash_password(password) == hashed_stored_password:
                    return actual_message
                else:
                    return "Incorrect password."
        return "No hidden message found or incorrect delimiter."

    except Exception as e:
        return f"Error revealing message: {e}"

def browse_input_image():
    global input_path
    input_path = filedialog.askopenfilename(title="Select Input Image", filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
    input_entry.delete(0, tk.END)
    input_entry.insert(0, input_path)

def decrypt_image():
    password = password_entry.get()

    if not input_path or not password:
        messagebox.showerror("Error", "Please select an image and enter a password.")
        return

    revealed_message = reveal_message(input_path, password)
    messagebox.showinfo("Revealed Message", revealed_message)

# GUI setup
root = tk.Tk()
root.title("Steganography Decryption")

input_label = tk.Label(root, text="Input Image:")
input_label.grid(row=0, column=0, sticky="w")

input_entry = tk.Entry(root, width=40)
input_entry.grid(row=0, column=1)

input_button = tk.Button(root, text="Browse", command=browse_input_image)
input_button.grid(row=0, column=2)

password_label = tk.Label(root, text="Password:")
password_label.grid(row=1, column=0, sticky="w")

password_entry = tk.Entry(root, show="*")
password_entry.grid(row=1, column=1)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_image)
decrypt_button.grid(row=2, column=1)

input_path = ""

root.mainloop()
