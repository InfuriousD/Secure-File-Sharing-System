import os
import sys
import threading
import time
from io import BytesIO

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from flask import Flask, request, jsonify, send_file, send_from_directory

from exceptions import NotAuthenticatedException, OtherException, OperationFailedException
from utils import calculate_sha256, is_jwt_about_to_expire, get_user_id_from_token
from utils import encrypt_symmetric_key, encrypt_symmetric_key_str, decrypt_symmetric_key
from utils import generate_symmetric_key, encrypt_file, decrypt_file
from utils import get_public_proof
from utils import load_config, load_private_key

app = Flask(__name__)

token_lock = threading.Lock()
session_token = {'s': None}

EXP_LIMIT = 10  # seconds
stop_heartbeat = threading.Event()
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "client_config.json")
client_config = load_config(CONFIG_PATH)

USERNAME = client_config["username"]
SERVER_URL = client_config["server_url"]
PRIV_KEY_PATH = client_config.get("private_key_path", None)
PASSWORD_PATH = client_config.get("password_path", None)
FILE_PRIV_KEY_PATH = client_config["file_private_key_path"]
FILE_PUB_KEY_PATH = client_config["file_public_key_path"]

req_session = requests.Session()


def get_message(resp):
    return resp.json().get("message", resp.text)


def set_token(token):
    # global session_token
    with token_lock:
        session_token["s"] = token


def get_token():
    # global session_token
    with token_lock:
        return session_token.get("s", None)


def send_renewal(auth_fn):
    while not stop_heartbeat.is_set():
        if not is_jwt_about_to_expire(get_token(), EXP_LIMIT):
            time.sleep(0.2)
            continue
        response = req_session.post(f"{SERVER_URL}/renew_session", headers=validata_session_get_headers())
        if response.status_code == 200:
            set_token(response.json()["session_token"])
            print("Session token renewed.")
        else:
            if not auth_fn():
                print("Failed to renew session token. Exiting.")
                exit(1)
            print("Session token renewed.")


def request_challenge():
    response = req_session.post(f"{SERVER_URL}/request_challenge", json={"username": USERNAME})
    if response.status_code == 200:
        return response.json()["challenge"]
    else:
        print("Failed to request challenge:", response.json().get("message"))
        raise OtherException()


def request_challenge_password():
    response = req_session.post(f"{SERVER_URL}/request_challenge_password", json={"username": USERNAME})
    if response.status_code == 200:
        return response.json()["challenge"]
    else:
        print("Failed to request challenge:", response.json().get("message"))
        raise OtherException()


def authenticate():
    challenge = request_challenge()
    if not challenge:
        return False

    # Load ECDSA private key
    private_key = load_private_key(PRIV_KEY_PATH)
    signed_challenge = private_key.sign(
        challenge.encode(),
        ECDSA(hashes.SHA256())
    )

    response = req_session.post(
        f"{SERVER_URL}/authenticate",
        json={"username": USERNAME, "signed_challenge": signed_challenge.hex()}
    )
    if response.status_code == 200:
        set_token(response.json()["session_token"])
        print("re/Authenticated successfully.")
        return True
    else:
        print("Authentication failed:", response.json().get("message"))
        return False


def authenticate_password():
    challenge = request_challenge_password()
    if not challenge:
        return False

    with open(PASSWORD_PATH, "r") as f:
        password = f.read().strip()

    salt, prime, gen, server_pub = challenge.split(":")
    user_proof = get_public_proof(USERNAME, password, salt, prime, gen, server_pub)
    user_proof = ':'.join(user_proof)

    response = req_session.post(
        f"{SERVER_URL}/authenticate_password",
        json={"username": USERNAME, "proof": user_proof}
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


def upload_file(file, download_limit=0, expiration_delta=3600):
    headers = validata_session_get_headers()
    file_data = file.read()
    file.seek(0)
    symmetric_key = generate_symmetric_key()
    encrypted_file_data = encrypt_file(file_data, symmetric_key)
    encrypted_key = encrypt_symmetric_key(symmetric_key, FILE_PUB_KEY_PATH)

    files = {"file": (file.filename, encrypted_file_data)}
    print(len(encrypted_file_data))
    data = {"encrypted_key": encrypted_key, "download_limit": download_limit,
            "expiration_delta": expiration_delta,
            "sha256_checksum": calculate_sha256(encrypted_file_data)}

    response = req_session.post(
        f"{SERVER_URL}/upload_file",
        files=files,
        data=data,
        headers=headers
    )

    if response.status_code != 200:
        raise OperationFailedException(response.status_code, get_message(response))


def download_file(file_id):
    headers = validata_session_get_headers()

    # Step 1: Get file info
    response = req_session.get(f"{SERVER_URL}/file_info/{file_id}", headers=headers)
    if response.status_code != 200:
        raise OperationFailedException(response.status_code, get_message(response))

    file_info = response.json()["file_info"]
    encrypted_key = file_info["encrypted_key"]
    file_name = file_info["filename"]

    # Step 2: Decrypt the symmetric key
    symmetric_key = decrypt_symmetric_key(encrypted_key, FILE_PRIV_KEY_PATH)

    # Step 3: Download and decrypt file
    response = requests.get(f"{SERVER_URL}/download_file/{file_id}", headers=headers)
    if response.status_code != 200:
        raise OperationFailedException(response.status_code, get_message(response))

    encrypted_data = response.content
    decrypted_data = decrypt_file(encrypted_data, symmetric_key)
    file = BytesIO(decrypted_data)
    file.seek(0)

    return file_name, file


def share_file(file_id, share_with_username, target_pub_key_str):
    headers = validata_session_get_headers()

    # Step 1: Get file info to retrieve the symmetric key
    response = req_session.get(f"{SERVER_URL}/file_info/{file_id}", headers=headers)
    if response.status_code != 200:
        raise OperationFailedException(response.status_code, get_message(response))

    file_info = response.json()["file_info"]
    encrypted_key = file_info["encrypted_key"]

    # Step 2: Decrypt the symmetric key
    symmetric_key = decrypt_symmetric_key(encrypted_key, FILE_PRIV_KEY_PATH)

    # Step 3: Encrypt symmetric key for the target user
    encrypted_key_for_target = encrypt_symmetric_key_str(symmetric_key, target_pub_key_str)

    # Step 4: Send the shared key to the server
    data = {
        "file_id": file_id,
        "share_with_username": share_with_username,
        "target_decryption_key": encrypted_key_for_target
    }
    response = req_session.post(f"{SERVER_URL}/share_file", json=data, headers=headers)

    if response.status_code != 200:
        raise OperationFailedException(response.status_code, get_message(response))


def list_files():
    headers = validata_session_get_headers()
    response = req_session.get(f"{SERVER_URL}/list_files", headers=headers)

    if response.status_code != 200:
        raise OperationFailedException(response.status_code, get_message(response))

    return response.json()["files"]


def delete_file(file_id):
    headers = validata_session_get_headers()
    response = req_session.delete(f"{SERVER_URL}/delete_file/{file_id}", headers=headers)

    if response.status_code != 200:
        raise OperationFailedException(response.status_code, get_message(response))


def get_target_pub_key(username):
    headers = validata_session_get_headers()
    response = req_session.get(f"{SERVER_URL}/encryption_key/{username}", headers=headers)

    if response.status_code == 200:
        return response.json()["encryption_key"]
    else:
        raise OperationFailedException(response.status_code, get_message(response))


@app.route("/download_file/<int:file_id>", methods=["GET"])
def download_file_route(file_id):
    try:
        file_name, file = download_file(file_id)
        return send_file(file, as_attachment=True, download_name=file_name)
    except OperationFailedException as e:
        return jsonify({"message": str(e)}), e.code


@app.route("/delete_file/<int:file_id>", methods=["DELETE"])
def delete_file_route(file_id):
    try:
        delete_file(file_id)
        return jsonify({"message": f"File {file_id} deleted successfully."}), 200
    except OperationFailedException as e:
        return jsonify({"message": str(e)}), e.code


@app.route("/list_files", methods=["GET"])
def list_files_route():
    try:
        files = list_files()
        return jsonify({"files": files, "user_id": get_user_id_from_token(get_token())}), 200
    except OperationFailedException as e:
        return jsonify({"message": str(e)}), e.code


@app.route("/upload_file", methods=["POST"])
def upload_file_route():
    try:
        download_limit = int(request.form["download_limit"])
        expiration_delta = int(request.form["expiration_delta"])
        file = request.files["file"]
        upload_file(file, download_limit, expiration_delta)
        return jsonify({"message": f"File {os.path.basename(file.filename)} uploaded successfully."}), 200
    except OperationFailedException as e:
        return jsonify({"message": str(e)}), e.code


@app.route("/share_file", methods=["POST"])
def share_file_route():
    try:
        file_id = int(request.json["file_id"])
        share_with_username = request.json["share_with_username"]
        target_decryption_key = get_target_pub_key(share_with_username)
        share_file(file_id, share_with_username, target_decryption_key)
        return jsonify({"message": f"File {file_id} shared with {share_with_username} successfully."}), 200
    except OperationFailedException as e:
        return jsonify({"message": str(e)}), e.code


@app.route("/")
def serve_html():
    return send_from_directory("html", "index.html")


@app.route('/resources/<path:filename>')
def serve_resources(filename):
    return send_from_directory('resources', filename)


if __name__ == '__main__':
    if USERNAME == "anonymous":
        print("Anonymous user is not allowed to use this client. Please use the command line client.")
        sys.exit(1)
    assert PRIV_KEY_PATH is not None or PASSWORD_PATH is not None, "Please provide either private key or password."
    authentication_fn = authenticate_password if PASSWORD_PATH is not None else authenticate
    if not authentication_fn():
        print("Failed to authenticate. Exiting.")
        exit(1)
    renewal_thread = threading.Thread(target=send_renewal, args=(authentication_fn,), daemon=True)
    renewal_thread.start()
    app.run(port=5001)
    stop_heartbeat.set()
    renewal_thread.join()
