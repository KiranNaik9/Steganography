import cv2
import os
import hashlib

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
        print(f"Message hidden successfully. Output saved to {output_path}")

    except Exception as e:
        print(f"Error hiding message: {e}")

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

def encrypt_image(input_path, message, password, output_path):
    """Encrypts an image with a hidden message."""
    hide_message(input_path, message, password, output_path)

def decrypt_image(input_path, password):
    """Decrypts a hidden message from an image."""
    return reveal_message(input_path, password)

if __name__ == "__main__":
    # Encryption Example:
    input_image_path_encrypt = input("Enter input image path: ")
    message_to_hide = input("Enter the secret message: ")
    password_encrypt = input("Enter the encryption password: ")

    base_name = os.path.splitext(os.path.basename(input_image_path_encrypt))[0]
    output_image_path_encrypt = os.path.join(os.path.dirname(input_image_path_encrypt), f"{base_name}_EncryptedOutput.png")

    if os.path.exists(input_image_path_encrypt):
        encrypt_image(input_image_path_encrypt, message_to_hide, password_encrypt, output_image_path_encrypt)

        # Decryption Example:
        input_image_path_decrypt = input("Enter the encrypted image path: ")
        password_decrypt = input("Enter the decryption password: ")

        revealed_message = decrypt_image(input_image_path_decrypt, password_decrypt)
        print(f"Revealed message: {revealed_message}")

    else:
        print(f"Error: input image {input_image_path_encrypt} not found.")
