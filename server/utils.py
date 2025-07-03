import datetime
import hashlib
import secrets
import time
from functools import wraps
from io import BytesIO

import jwt
import psycopg2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import request, jsonify
from srptools import SRPContext, SRPServerSession

from config import SERVER_CONFIG

JWT_SK = SERVER_CONFIG.jwt_sk
JWT_ALGORITHM = "HS256"
MAX_RENEW_ATTEMPTS = SERVER_CONFIG.max_renewal
TOKEN_TIMEOUT = SERVER_CONFIG.timeout


def get_user_id_by_username(username, cursor: psycopg2._psycopg.cursor):
    cursor.execute("SELECT user_id FROM user_credentials WHERE username = %s", (username,))
    result = cursor.fetchone()
    if not result:
        return None
    return result[0]


def get_username_by_user_id(user_id, cursor: psycopg2._psycopg.cursor):
    cursor.execute("SELECT username FROM user_credentials WHERE user_id = %s", (user_id,))
    result = cursor.fetchone()
    if not result:
        return None
    return result[0]


def get_user_encryption_key_by_username(username, cursor: psycopg2._psycopg.cursor):
    cursor.execute("SELECT encryption_key FROM user_credentials WHERE username = %s", (username,))
    result = cursor.fetchone()
    if not result:
        return None
    return result[0]


def create_access_token(user_id, renewal=0):
    return jwt.encode(
        {
            "user_id": user_id,
            "renewal": renewal,
            "exp": int(
                (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=TOKEN_TIMEOUT)).timestamp()),
        },
        JWT_SK,
        algorithm=JWT_ALGORITHM,
    )


def verify_access_token(token):
    try:
        data = jwt.decode(token, JWT_SK, algorithms=[JWT_ALGORITHM], options={"verify_exp": False})
        current = datetime.datetime.now(datetime.timezone.utc).timestamp()

        if data["exp"] < int(current):
            return None
        return data
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def renew_access_token(token):
    decoded_token = verify_access_token(token)
    if not decoded_token:
        return None
    if decoded_token["renewal"] >= MAX_RENEW_ATTEMPTS:
        return None
    return create_access_token(decoded_token["user_id"], decoded_token["renewal"] + 1)


def validate_session(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"message": "Authorization header missing or malformed"}), 401

        token = auth_header.split("Bearer ")[1]

        token_data = verify_access_token(token)
        if not token_data:
            return jsonify({"message": "Invalid or expired token"}), 401

        request.user_id = token_data["user_id"]

        return func(*args, **kwargs)

    return wrapper


def generate_storage_filename(filename, user_id):
    timestamp = str(int(time.time()))
    unique_string = f"{filename}_{user_id}_{timestamp}"
    hash_object = hashlib.sha256(unique_string.encode())
    hashed_filename = hash_object.hexdigest()

    storage_filename = hashed_filename[:100]
    return storage_filename


def calculate_sha256(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def encrypt_file(file_data):
    iv = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(SERVER_CONFIG.aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    return iv + encrypted_data + encryptor.tag


def decrypt_file(encrypted_data):
    iv = encrypted_data[:12]
    tag = encrypted_data[-16:]
    ciphertext = encrypted_data[12:-16]

    cipher = Cipher(algorithms.AES(SERVER_CONFIG.aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def data_to_file(data):
    file = BytesIO(data)
    file.seek(0)
    return file


def bytes_to_readable(size):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def get_public_private(username, prime, gen, verifier):
    session = SRPServerSession(SRPContext(username, prime=prime, generator=gen), verifier)
    return session.public, session.private


def verify_client(username, prime, gen, salt, verifier, private, client_public, proof):
    server_session = SRPServerSession(SRPContext(username, prime=prime, generator=gen), verifier, private=private)
    server_session.process(client_public, salt)
    return server_session.verify_proof(proof, base64=True)
