import base64
import io
import os
import zipfile

from cryptography.exceptions import InvalidTag, InvalidKey, InvalidSignature

from utils import decrypt_file, decrypt_symmetric_key


def main():
    zip_file_path = input("Enter the path to the encrypted zip file: ")
    private_key_path = input("Enter the path to your private key: ")

    with open(zip_file_path, "rb") as f:
        zip_data = f.read()

    zip_buffer = io.BytesIO(zip_data)

    with zipfile.ZipFile(zip_buffer, "r") as zip_file:
        encrypted_data = zip_file.read("encrypted_data.bin")
        encrypted_key = zip_file.read("encrypted_key.bin")

    encrypted_key_b64 = base64.b64encode(encrypted_key).decode()

    try:
        symmetric_key = decrypt_symmetric_key(encrypted_key_b64, private_key_path)
    except (InvalidTag, InvalidKey, InvalidSignature):
        print("Failed to decrypt the key.")
        return

    decrypted_data = decrypt_file(encrypted_data, symmetric_key)
    print("File decrypted successfully.")

    file_save_path = input("Enter the path to save the decrypted file: ")
    filename = os.path.basename(zip_file_path)
    filename = filename[:filename.rfind(".")]

    with open(os.path.join(file_save_path, filename), "wb") as f:
        f.write(decrypted_data)

    print("File saved successfully.")


if __name__ == "__main__":
    main()
