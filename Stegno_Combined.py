import cv2
import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

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

def browse_input_encrypt():
    global input_path_encrypt
    input_path_encrypt = filedialog.askopenfilename(title="Select Input Image", filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
    input_entry_encrypt.delete(0, tk.END)
    input_entry_encrypt.insert(0, input_path_encrypt)

def encrypt_image():
    message = message_text_encrypt.get("1.0", "end-1c")
    password = password_entry_encrypt.get()

    if not input_path_encrypt or not message or not password:
        messagebox.showerror("Error", "Please fill all fields.")
        return

    base_name = os.path.splitext(os.path.basename(input_path_encrypt))[0]
    output_path = os.path.join(os.path.dirname(input_path_encrypt), f"{base_name}_EncryptedOutput.png")

    hide_message(input_path_encrypt, message, password, output_path)

def browse_input_decrypt():
    global input_path_decrypt
    input_path_decrypt = filedialog.askopenfilename(title="Select Input Image", filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
    input_entry_decrypt.delete(0, tk.END)
    input_entry_decrypt.insert(0, input_path_decrypt)

def decrypt_image():
    password = password_entry_decrypt.get()

    if not input_path_decrypt or not password:
        messagebox.showerror("Error", "Please select an image and enter a password.")
        return

    revealed_message = reveal_message(input_path_decrypt, password)
    messagebox.showinfo("Revealed Message", revealed_message)

# GUI setup
root = tk.Tk()
root.title("Image Steganography")

notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True)

# Encryption Tab
encrypt_tab = ttk.Frame(notebook)
notebook.add(encrypt_tab, text="Encryption")

input_label_encrypt = tk.Label(encrypt_tab, text="Input Image:")
input_label_encrypt.grid(row=0, column=0, sticky="w")
input_entry_encrypt = tk.Entry(encrypt_tab, width=40)
input_entry_encrypt.grid(row=0, column=1)
input_button_encrypt = tk.Button(encrypt_tab, text="Browse", command=browse_input_encrypt)
input_button_encrypt.grid(row=0, column=2)

message_label_encrypt = tk.Label(encrypt_tab, text="Message:")
message_label_encrypt.grid(row=1, column=0, sticky="w")
message_text_encrypt = scrolledtext.ScrolledText(encrypt_tab, height=5, width=40)
message_text_encrypt.grid(row=1, column=1, columnspan=2)

password_label_encrypt = tk.Label(encrypt_tab, text="Password:")
password_label_encrypt.grid(row=2, column=0, sticky="w")
password_entry_encrypt = tk.Entry(encrypt_tab, show="*")
password_entry_encrypt.grid(row=2, column=1, columnspan=2)

encrypt_button = tk.Button(encrypt_tab, text="Encrypt", command=encrypt_image)
encrypt_button.grid(row=3, column=1)

# Decryption Tab
decrypt_tab = ttk.Frame(notebook)
notebook.add(decrypt_tab, text="Decryption")

input_label_decrypt = tk.Label(decrypt_tab, text="Input Image:")
input_label_decrypt.grid(row=0, column=0, sticky="w")
input_entry_decrypt = tk.Entry(decrypt_tab, width=40)
input_entry_decrypt.grid(row=0, column=1)
input_button_decrypt = tk.Button(decrypt_tab, text="Browse", command=browse_input_decrypt)
input_button_decrypt.grid(row=0, column=2)

password_label_decrypt = tk.Label(decrypt_tab, text="Password:")
password_label_decrypt.grid(row=1, column=0, sticky="w")
password_entry_decrypt = tk.Entry(decrypt_tab, show="*")
password_entry_decrypt.grid(row=1, column=1, columnspan=2)

decrypt_button = tk.Button(decrypt_tab, text="Decrypt", command=decrypt_image)
decrypt_button.grid(row=2, column=1)

input_path_encrypt = ""
input_path_decrypt = ""

root.mainloop()
