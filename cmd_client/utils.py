import base64
import datetime
import hashlib
import json
import secrets

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1, ECDH
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from srptools import SRPContext, SRPClientSession


def calculate_sha256(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def is_jwt_about_to_expire(token, limit):
    decoded_token = jwt.decode(token, options={"verify_signature": False})
    exp_time_utc = datetime.datetime.fromtimestamp(decoded_token["exp"], datetime.timezone.utc)
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    return exp_time_utc - now_utc < datetime.timedelta(seconds=limit)


def load_config(config_path):
    with open(config_path, "r") as f:
        return json.load(f)


def load_private_key(path):
    with open(path, "rb") as key_file:
        return load_pem_private_key(key_file.read(), password=None, backend=default_backend())


def load_public_key(path):
    with open(path, "rb") as key_file:
        return load_pem_public_key(key_file.read(), backend=default_backend())


def generate_symmetric_key():
    return secrets.token_bytes(32)


def encrypt_file(file_path, symmetric_key):
    with open(file_path, "rb") as file:
        file_data = file.read()

    iv = secrets.token_bytes(12)  # GCM typically uses a 12-byte IV
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    # The tag provides integrity verification
    return iv + encrypted_data + encryptor.tag


def decrypt_file(encrypted_data, symmetric_key):
    iv = encrypted_data[:12]
    tag = encrypted_data[-16:]
    ciphertext = encrypted_data[12:-16]

    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _encrypt_symmetric_key_base(symmetric_key, public_key):
    ephemeral_private_key = generate_private_key(SECP256R1(), backend=default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Derive shared secret
    shared_secret = ephemeral_private_key.exchange(ECDH(), public_key)

    # Derive encryption key from shared secret
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecies key encryption"
    ).derive(shared_secret)

    # Encrypt the symmetric key using AES-GCM
    iv = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_symmetric_key = encryptor.update(symmetric_key) + encryptor.finalize()

    # Combine ephemeral public key, IV, and encrypted symmetric key
    ephemeral_public_key_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ephemeral_key_length = len(ephemeral_public_key_bytes).to_bytes(2, "big")  # 2 bytes for length
    return base64.b64encode(
        iv + encryptor.tag + ephemeral_key_length + ephemeral_public_key_bytes + encrypted_symmetric_key).decode()


def encrypt_symmetric_key(symmetric_key, public_key_path):
    public_key = load_public_key(public_key_path)
    return _encrypt_symmetric_key_base(symmetric_key, public_key)


def encrypt_symmetric_key_str(symmetric_key, public_key_str):
    public_key_data = base64.b64decode(public_key_str)
    public_key = load_pem_public_key(public_key_data, backend=default_backend())
    return _encrypt_symmetric_key_base(symmetric_key, public_key)


def decrypt_symmetric_key(encrypted_key_b64, private_key_path):
    private_key = load_private_key(private_key_path)
    encrypted_key_data = base64.b64decode(encrypted_key_b64)

    # Extract components
    iv = encrypted_key_data[:12]
    tag = encrypted_key_data[12:28]
    ephemeral_key_length = int.from_bytes(encrypted_key_data[28:30], "big")  # Extract the 2-byte length
    ephemeral_public_key_bytes = encrypted_key_data[30:30 + ephemeral_key_length]
    encrypted_symmetric_key = encrypted_key_data[30 + ephemeral_key_length:]

    # Load ephemeral public key
    ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_key_bytes, backend=default_backend())

    # Derive shared secret
    shared_secret = private_key.exchange(ECDH(), ephemeral_public_key)

    # Derive decryption key from shared secret
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecies key encryption"
    ).derive(shared_secret)

    # Decrypt the symmetric key using AES-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_symmetric_key) + decryptor.finalize()


def get_public_proof(username, password, salt, prime, gen, server_pub):
    session = SRPClientSession(SRPContext(username, password, prime=prime, generator=gen))
    session.process(server_pub, salt)
    client_pub, client_proof = session.public, session.key_proof_b64
    return client_pub, client_proof
