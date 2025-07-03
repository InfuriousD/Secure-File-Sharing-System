import os
import sys
import threading
import time

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from exceptions import NotAuthenticatedException, OtherException
from utils import calculate_sha256, is_jwt_about_to_expire
from utils import encrypt_symmetric_key, encrypt_symmetric_key_str, decrypt_symmetric_key
from utils import generate_symmetric_key, encrypt_file, decrypt_file
from utils import get_public_proof
from utils import load_config, load_private_key

session_token = {'s': None}
token_lock = threading.Lock()

EXP_LIMIT = 10  # seconds
stop_heartbeat = threading.Event()

req_session = requests.Session()


def set_token(token):
    # global session_token
    with token_lock:
        session_token["s"] = token


def get_token():
    # global session_token
    with token_lock:
        return session_token.get("s", None)


def send_renewal(server_url, auth_lambda):
    while not stop_heartbeat.is_set():
        if not is_jwt_about_to_expire(get_token(), EXP_LIMIT):
            time.sleep(0.2)
            continue
        response = req_session.post(f"{server_url}/renew_session", headers=validata_session_get_headers())
        if response.status_code == 200:
            set_token(response.json()["session_token"])
            print("Session token renewed.")
        else:
            if not auth_lambda():
                print("Failed to renew session token. Exiting.")
                exit(1)
            print("Session token renewed.")


def request_challenge(server_url, username):
    response = req_session.post(f"{server_url}/request_challenge", json={"username": username})
    if response.status_code == 200:
        return response.json()["challenge"]
    else:
        print("Failed to request challenge:", response.json().get("message"))
        raise OtherException()


def request_challenge_password(server_url, username):
    response = req_session.post(f"{server_url}/request_challenge_password", json={"username": username})
    if response.status_code == 200:
        return response.json()["challenge"]
    else:
        print("Failed to request challenge:", response.json().get("message"))
        raise OtherException()


def authenticate(server_url, username, priv_key_path):
    challenge = request_challenge(server_url, username)
    if not challenge:
        return False

    # Load ECDSA private key
    private_key = load_private_key(priv_key_path)
    signed_challenge = private_key.sign(
        challenge.encode(),
        ECDSA(hashes.SHA256())
    )

    response = req_session.post(
        f"{server_url}/authenticate",
        json={"username": username, "signed_challenge": signed_challenge.hex()}
    )
    if response.status_code == 200:
        set_token(response.json()["session_token"])
        print("re/Authenticated successfully.")
        return True
    else:
        print("Authentication failed:", response.json().get("message"))
        return False


def authenticate_password(server_url, username, password_path):
    challenge = request_challenge_password(server_url, username)
    if not challenge:
        return False

    with open(password_path, "r") as f:
        password = f.read().strip()

    salt, prime, gen, server_pub = challenge.split(":")
    user_proof = get_public_proof(username, password, salt, prime, gen, server_pub)
    user_proof = ':'.join(user_proof)

    response = req_session.post(
        f"{server_url}/authenticate_password",
        json={"username": username, "proof": user_proof}
    )
    if response.status_code == 200:
        set_token(response.json()["session_token"])
        print("Authenticated successfully.")
        return True
    else:
        print("Authentication failed:", response.json().get("message"))
        return False


def validata_session_get_headers():
    s_token = get_token()
    if not s_token:
        print("No valid session token. Please authenticate first.")
        raise NotAuthenticatedException()

    return {"Authorization": f'Bearer {s_token}'}


def upload_file(server_url, file_path, file_enc_key_path, download_limit=0, expiration_delta=3600):
    headers = validata_session_get_headers()

    symmetric_key = generate_symmetric_key()
    encrypted_file_data = encrypt_file(file_path, symmetric_key)
    encrypted_key = encrypt_symmetric_key(symmetric_key, file_enc_key_path)

    file_name = os.path.basename(file_path)
    files = {"file": (file_name, encrypted_file_data)}
    data = {"encrypted_key": encrypted_key, "download_limit": download_limit,
            "expiration_delta": expiration_delta,
            "sha256_checksum": calculate_sha256(encrypted_file_data)}

    response = req_session.post(
        f"{server_url}/upload_file",
        files=files,
        data=data,
        headers=headers
    )

    if response.status_code == 200:
        print("File uploaded successfully.")
    else:
        print("Upload failed:", response.json().get("message"))
        raise OtherException()


def download_file(server_url, file_id, file_priv_key_path, save_path):
    headers = validata_session_get_headers()

    # Step 1: Get file info
    response = req_session.get(f"{server_url}/file_info/{file_id}", headers=headers)
    if response.status_code != 200:
        print("Failed to get file info:", response.json().get("message"))
        return

    file_info = response.json()["file_info"]
    encrypted_key = file_info["encrypted_key"]
    filename = file_info["filename"]

    # Step 2: Decrypt the symmetric key
    symmetric_key = decrypt_symmetric_key(encrypted_key, file_priv_key_path)

    # Step 3: Download and decrypt file
    response = requests.get(f"{server_url}/download_file/{file_id}", headers=headers)
    if response.status_code != 200:
        print("Failed to download file:", response.json().get("message"))
        raise OtherException()

    encrypted_data = response.content
    decrypted_data = decrypt_file(encrypted_data, symmetric_key)

    with open(os.path.join(save_path, filename), "wb") as f:
        f.write(decrypted_data)
    print(f"File downloaded and saved to {save_path}")


def share_file(server_url, file_id, share_with_username, file_priv_key_path, target_pub_key_str):
    headers = validata_session_get_headers()

    # Step 1: Get file info to retrieve the symmetric key
    response = req_session.get(f"{server_url}/file_info/{file_id}", headers=headers)
    if response.status_code != 200:
        print("Failed to get file info:", response.json().get("message"))
        raise OtherException()

    file_info = response.json()["file_info"]
    encrypted_key = file_info["encrypted_key"]

    # Step 2: Decrypt the symmetric key
    symmetric_key = decrypt_symmetric_key(encrypted_key, file_priv_key_path)

    # Step 3: Encrypt symmetric key for the target user
    encrypted_key_for_target = encrypt_symmetric_key_str(symmetric_key, target_pub_key_str)

    # Step 4: Send the shared key to the server
    data = {
        "file_id": file_id,
        "share_with_username": share_with_username,
        "target_decryption_key": encrypted_key_for_target
    }
    response = req_session.post(f"{server_url}/share_file", json=data, headers=headers)

    if response.status_code == 200:
        print("File shared successfully.")
    else:
        print("File sharing failed:", response.json().get("message"))


def list_files(server_url):
    headers = validata_session_get_headers()
    response = req_session.get(f"{server_url}/list_files", headers=headers)

    if response.status_code == 200:
        files = response.json()["files"]
        for file in files:
            print(
                f"File ID: {file['file_id']}, Name: {file['filename']}, Owner: {file['owner_id']}, Downloads: {file['download_count']}/{file['download_limit']}")
    else:
        print("Failed to list files:", response.json().get("message"))
        raise OtherException()


def delete_file(server_url, file_id):
    headers = validata_session_get_headers()
    response = req_session.delete(f"{server_url}/delete_file/{file_id}", headers=headers)

    if response.status_code == 200:
        print("File deleted successfully.")
    else:
        print("Failed to delete file:", response.json().get("message"))
        raise OtherException()


def get_target_pub_key(server_url, username):
    headers = validata_session_get_headers()
    response = req_session.get(f"{server_url}/encryption_key/{username}", headers=headers)

    if response.status_code == 200:
        return response.json()["encryption_key"]
    else:
        print("Failed to get public key:", response.json().get("message"))
        raise OtherException()


def main():
    if len(sys.argv) < 2:
        print("Usage: python client.py <path_to_config>")
        return

    config_path = sys.argv[1]
    client_config = load_config(config_path)

    username = client_config["username"]
    if username == "anonymous":
        print("Anonymous user should use `main_anonymous.py`.")
        return 1
    server_url = client_config["server_url"]
    priv_key_path = client_config.get("private_key_path", None)
    password_path = client_config.get("password_path", None)
    assert priv_key_path or password_path, "Either private key or password should be provided."

    file_priv_key_path = client_config["file_private_key_path"]
    file_pub_key_path = client_config["file_public_key_path"]

    if priv_key_path is not None:
        auth_lambda = lambda: authenticate(server_url, username, priv_key_path)
    else:
        auth_lambda = lambda: authenticate_password(server_url, username, password_path)

    if not auth_lambda():
        print("Failed to authenticate. Exiting.")
        return 1

    # Start heartbeat thread
    heartbeat_thread = threading.Thread(target=send_renewal, args=(server_url, auth_lambda))
    heartbeat_thread.start()

    try:
        while True:
            try:
                action = input("Choose an action (upload, download, share, list, delete, exit): ").lower()

                if action == "upload":
                    file_path = input("Enter the file path to upload: ")
                    if os.path.exists(file_path):
                        download_limit = int(input("Enter the download limit (0 for unlimited): "))
                        expiration_delta = input("Enter the expiration time <number>(s/m/h/d): ")
                        expiration_delta_unit = expiration_delta[-1]
                        expiration_delta = int(expiration_delta[:-1])
                        units_time = {"s": 1, "m": 60, "h": 3600, "d": 86400}
                        expiration_delta = expiration_delta * units_time.get(expiration_delta_unit, 1)

                        upload_file(server_url, file_path, file_pub_key_path, download_limit, expiration_delta)
                    else:
                        print("File not found.")

                elif action == "download":
                    file_id = int(input("Enter file ID to download: "))
                    save_path = input("Enter the path to save the downloaded file: ")
                    if os.path.exists(save_path):
                        download_file(server_url, file_id, file_priv_key_path, save_path)
                    else:
                        print("Invalid save path.")

                elif action == "share":
                    file_id = int(input("Enter file ID to share: "))
                    share_with_username = input("Enter the username to share with: ")
                    target_pub_key_str = get_target_pub_key(server_url, share_with_username)
                    share_file(server_url, file_id, share_with_username, file_priv_key_path, target_pub_key_str)

                elif action == "list":
                    list_files(server_url)

                elif action == "delete":
                    file_id = int(input("Enter file ID to delete: "))
                    delete_file(server_url, file_id)

                elif action == "exit":
                    print("Exiting.")
                    break

                else:
                    print("Invalid action. Please choose again.")
            except OtherException:
                continue
            except NotAuthenticatedException:
                if not auth_lambda():
                    print("Failed to re-authenticate. Exiting.")
                    break
    except KeyboardInterrupt:
        print("Exiting.")
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join()


if __name__ == '__main__':
    main()
