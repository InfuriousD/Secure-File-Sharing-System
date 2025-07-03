import base64
import io
import os
import sys
import zipfile

import requests
from cryptography.exceptions import InvalidTag, InvalidKey, InvalidSignature

from exceptions import OtherException
from utils import calculate_sha256
from utils import encrypt_symmetric_key, decrypt_symmetric_key
from utils import generate_symmetric_key, encrypt_file, decrypt_file
from utils import load_config

req_session = requests.Session()


def upload_file(server_url, file_path, file_enc_key_path):
    symmetric_key = generate_symmetric_key()
    encrypted_file_data = encrypt_file(file_path, symmetric_key)
    encrypted_key = encrypt_symmetric_key(symmetric_key, file_enc_key_path)

    file_name = os.path.basename(file_path)
    files = {"file": (file_name, encrypted_file_data)}
    data = {"encrypted_key": encrypted_key,
            "sha256_checksum": calculate_sha256(encrypted_file_data)}

    response = req_session.post(
        f"{server_url}/anonymous/upload_file",
        files=files,
        data=data
    )

    if response.status_code == 200:
        print("File uploaded successfully")
    else:
        print("Upload failed:", response.json().get("message"))
        raise OtherException()


def download_file(server_url, file_id, save_path, file_priv_key_path=None):
    response = req_session.get(f"{server_url}/anonymous/file_info/{file_id}")
    if response.status_code != 200:
        print("Failed to retrieve file info:", response.json().get("message"))
        return

    file_info = response.json()["file_info"]
    encrypted_key = file_info["encrypted_key"]
    filename = file_info["filename"]

    symmetric_key = None
    try:
        symmetric_key = decrypt_symmetric_key(encrypted_key, file_priv_key_path)
    except (InvalidTag, InvalidKey, InvalidSignature):
        pass

    response = requests.get(f"{server_url}/anonymous/download_file/{file_id}")
    if response.status_code != 200:
        print("Failed to download file:", response.json().get("message"))
        raise OtherException()

    encrypted_data = response.content
    if symmetric_key:
        decrypted_data = decrypt_file(encrypted_data, symmetric_key)
        with open(os.path.join(save_path, filename), "wb") as f:
            f.write(decrypted_data)
        print(f"File downloaded and decrypted.")
    else:
        encrypted_key = base64.b64decode(encrypted_key)
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr("encrypted_data.bin", encrypted_data)
            zip_file.writestr("encrypted_key.bin", encrypted_key)
        with open(os.path.join(save_path, f"{filename}.zip"), "wb") as f:
            f.write(zip_buffer.getvalue())
        print(f"File downloaded and saved as a zip file (Key mismatch).")


def list_files(server_url):
    response = req_session.get(f"{server_url}/anonymous/list_files")
    if response.status_code != 200:
        print("Failed to retrieve file list:", response.json().get("message"))
        return

    file_list = response.json()["files"]
    for file in file_list:
        print(f"File ID: {file['file_id']}, Filename: {file['filename']}, Expiration: {file['expiration_timestamp']}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python main_anonymous.py <config_file>")
        return

    client_config = load_config(sys.argv[1])

    username = client_config["username"]
    if username != "anonymous":
        print("Non anonymous user should use `main.py`.")
        return 1
    server_url = client_config["server_url"]
    file_priv_key_path = client_config["file_private_key_path"]
    file_pub_key_path = client_config["file_public_key_path"]

    try:
        while True:
            action = input("Choose an action (upload, download, list, exit): ")

            if action == "upload":
                file_path = input("Enter the file path to upload: ")
                if os.path.exists(file_path):
                    upload_file(server_url, file_path, file_pub_key_path)
                else:
                    print("File not found.")

            elif action == "download":
                file_id = input("Enter file ID to download: ")
                save_path = input("Enter the path to save the downloaded file: ")
                if os.path.exists(save_path):
                    download_file(server_url, file_id, save_path, file_priv_key_path)
                else:
                    print("Invalid save path.")

            elif action == "list":
                list_files(server_url)

            elif action == "exit":
                print("Exiting.")
                break

            else:
                print("Invalid action. Please choose again.")
    except KeyboardInterrupt:
        print("Exiting.")


if __name__ == "__main__":
    main()
