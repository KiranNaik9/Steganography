# steganography_encryption.py

import cv2
import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def hide_message(image_path, message, password, output_path):
    """Hides a message within an image using LSB steganography with password protection."""
    try:
        img = cv2.imread(image_path)
        if img is None:
            raise FileNotFoundError(f"Image not found at {image_path}")

        hashed_password = hash_password(password)
        message_with_password = f"{hashed_password}::{message}#####"
        message_binary = ''.join(format(ord(char), '08b') for char in message_with_password)
        message_len = len(message_binary)

        img_height, img_width, _ = img.shape
        max_bytes = img_height * img_width * 3 // 8

        if message_len > max_bytes:
            raise ValueError("Message too large to hide in image.")

        message_index = 0
        for i in range(img_height):
            for j in range(img_width):
                for k in range(3):
                    if message_index < message_len:
                        bit = int(message_binary[message_index])
                        pixel = img[i, j, k]
                        if pixel % 2 != bit:
                            if bit == 1:
                                if pixel == 255:
                                    img[i, j, k] = 254
                                else:
                                    img[i, j, k] += 1
                            else:
                                if pixel == 0:
                                    img[i, j, k] = 1
                                else:
                                    img[i, j, k] -= 1

                        message_index += 1
                    else:
                        break
                if message_index >= message_len:
                    break
            if message_index >= message_len:
                break

        cv2.imwrite(output_path, img)
        messagebox.showinfo("Success", f"Message hidden successfully. Output saved to {output_path}")

    except Exception as e:
        messagebox.showerror("Error", f"Error hiding message: {e}")

def browse_input_image():
    global input_path
    input_path = filedialog.askopenfilename(title="Select Input Image", filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
    input_entry.delete(0, tk.END)
    input_entry.insert(0, input_path)

def encrypt_image():
    message = message_entry.get("1.0", "end-1c")
    password = password_entry.get()

    if not input_path or not message or not password:
        messagebox.showerror("Error", "Please fill all fields.")
        return

    base_name = os.path.splitext(os.path.basename(input_path))[0]
    output_path = os.path.join(os.path.dirname(input_path), f"{base_name}_EncryptedOutput.png")

    hide_message(input_path, message, password, output_path)

# GUI setup
root = tk.Tk()
root.title("Steganography Encryption")

input_label = tk.Label(root, text="Input Image:")
input_label.grid(row=0, column=0, sticky="w")

input_entry = tk.Entry(root, width=40)
input_entry.grid(row=0, column=1)

input_button = tk.Button(root, text="Browse", command=browse_input_image)
input_button.grid(row=0, column=2)

message_label = tk.Label(root, text="Message:")
message_label.grid(row=1, column=0, sticky="w")

message_entry = tk.Text(root, height=5, width=40)
message_entry.grid(row=1, column=1, columnspan=2)

password_label = tk.Label(root, text="Password:")
password_label.grid(row=2, column=0, sticky="w")

password_entry = tk.Entry(root, show="*")
password_entry.grid(row=2, column=1, columnspan=2)

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_image)
encrypt_button.grid(row=3, column=1)

input_path = ""

root.mainloop()
