import base64
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import Blueprint, request, jsonify

from db import get_db_connection
from utils import create_access_token, renew_access_token, validate_session
from utils import get_public_private, verify_client

auth_bp = Blueprint("auth", __name__)


def clear_last_challenge(user_id, conn, cursor):
    cursor.execute("UPDATE user_credentials SET last_challenge = NULL WHERE user_id = %s", (user_id,))
    conn.commit()


@auth_bp.route('/request_challenge', methods=['POST'])
def request_challenge():
    data = request.json
    username = data.get("username")
    conn = get_db_connection()
    cursor = conn.cursor()
    # Retrieve user's public key and user ID from the database
    cursor.execute("SELECT public_key, user_id FROM user_credentials WHERE username = %s", (username,))
    result = cursor.fetchone()
    if not result:
        return jsonify({"message": "User not found"}), 404

    # public_key_b64, user_id = result

    # Generate a random challenge and store it
    challenge = base64.b64encode(os.urandom(32)).decode()
    cursor.execute("UPDATE user_credentials SET last_challenge = %s WHERE username = %s", (challenge, username))
    conn.commit()

    return jsonify({"challenge": challenge}), 200


@auth_bp.route('/request_challenge_password', methods=['POST'])
def request_challenge_password():
    data = request.json
    username = data.get("username")
    conn = get_db_connection()
    cursor = conn.cursor()
    # Retrieve user's password hash and user ID from the database
    cursor.execute("SELECT verifier, salt, user_id FROM user_credentials WHERE username = %s", (username,))
    result = cursor.fetchone()
    if not result:
        return jsonify({"message": "User not found"}), 404

    verifier, salt, user_id = result
    if not verifier or not salt:
        return jsonify({"message": "No password found for user"}), 400
    _, prime, gen = salt.split(':')
    s_pub, s_priv = get_public_private(username, prime, gen, verifier)
    challenge = salt + ':' + s_pub

    cursor.execute("UPDATE user_credentials SET last_challenge = %s WHERE username = %s", (s_priv, username))
    conn.commit()

    return jsonify({"challenge": challenge}), 200


# Endpoint to authenticate using the signed challenge-response
@auth_bp.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    username = data.get("username")
    signed_challenge = bytes.fromhex(data.get("signed_challenge"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Retrieve user's public key, user ID, and last challenge from the database
    cursor.execute("SELECT public_key, user_id, last_challenge FROM user_credentials WHERE username = %s", (username,))
    result = cursor.fetchone()
    if not result:
        return jsonify({"message": "User not found"}), 404

    public_key_b64, user_id, challenge = result
    clear_last_challenge(user_id, conn, cursor)

    public_key_data = base64.b64decode(public_key_b64)
    public_key = load_pem_public_key(public_key_data, backend=default_backend())

    try:
        # Verify the signed challenge using the stored ECDSA public key
        public_key.verify(
            signed_challenge,
            challenge.encode(),
            ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        return jsonify({"message": "Authentication failed"}), 401
    except Exception as e:
        return jsonify({"message": f"An unexpected error occurred: {str(e)}"}), 500
    session_token = create_access_token(user_id)
    return jsonify({"session_token": session_token}), 200


@auth_bp.route('/authenticate_password', methods=['POST'])
def authenticate_password():
    data = request.json
    username = data.get("username")
    proof = data.get("proof")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT verifier, salt, user_id, last_challenge FROM user_credentials WHERE username = %s",
                   (username,))
    result = cursor.fetchone()
    if not result:
        return jsonify({"message": "User not found"}), 404

    verifier, salt, user_id, challenge = result
    clear_last_challenge(user_id, conn, cursor)
    if not verifier or not salt:
        return jsonify({"message": "No password found for user"}), 400
    salt, prime, gen = salt.split(':')
    c_pub, proof = proof.split(':')
    if not verify_client(username, prime, gen, salt, verifier, challenge, c_pub, proof):
        return jsonify({"message": "Authentication failed"}), 401

    session_token = create_access_token(user_id)
    return jsonify({"session_token": session_token}), 200


# Endpoint to renew an existing session token
@auth_bp.route('/renew_session', methods=['POST'])
@validate_session
def renew_session():
    auth_header = request.headers.get("Authorization")
    token = auth_header.split("Bearer ")[1]
    token_data = renew_access_token(token)
    if not token_data:
        return jsonify({"message": "Session renewal failed"}), 401

    return jsonify({"session_token": token_data}), 200
