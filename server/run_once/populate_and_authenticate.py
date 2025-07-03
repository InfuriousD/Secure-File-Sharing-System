import base64
import json
import os

import psycopg2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from srptools import SRPContext, SRPServerSession, SRPClientSession

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_DATA_PATH = os.path.join(BASE_DIR, "../../example_users/user_data.json")

# Connect to PostgreSQL
conn = psycopg2.connect(
    dbname="cnt5410project",
    user="cnt5410_mgr",
    password="strong_password",
    host="localhost"
)
cursor = conn.cursor()


def get_verifier(username, password):
    """Generate the verifier for the user using SRP."""
    context = SRPContext(username, password)
    username, verifier, salt = context.get_user_data_triplet(base64=False)
    prime, gen = context.prime, context.generator
    return verifier, ':'.join([salt, prime, gen])


# -------------------------------
# Functions for Public Key Handling
# -------------------------------

def read_public_key(public_key_path):
    """Load and clean the public key in PEM format."""
    with open(public_key_path, "rb") as key_file:
        public_key_data = key_file.read()
    return public_key_data


def load_private_key(private_key_path):
    """Load the private key in PEM format for signing."""
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def sign_challenge(private_key_path, challenge):
    """Sign a challenge with the user's private key."""
    private_key = load_private_key(private_key_path)
    signed_challenge = private_key.sign(
        challenge.encode(),
        ECDSA(hashes.SHA256())
    )
    return signed_challenge.hex()


# -------------------------------
# Database Population
# -------------------------------

def populate_database(user_data_file):
    """Populate the database with user credentials."""
    with open(user_data_file, "r") as f:
        users = json.load(f)

    for user in users:
        verifier = None
        salt = None
        public_key_b64 = None

        # Process password if provided
        if "password_path" in user:
            password_path = os.path.join(os.path.dirname(user_data_file), user["password_path"])
            with open(password_path, "r") as password_file:
                password = password_file.read().strip()

            # Derive the key
            verifier, salt = get_verifier(user["username"], password)

        # Process public key if provided
        if "public_key_path" in user:
            public_key_path = os.path.join(os.path.dirname(user_data_file), user["public_key_path"])
            public_key_data = read_public_key(public_key_path)
            public_key_b64 = base64.b64encode(public_key_data).decode('utf-8')

        # Process file encryption key
        file_public_key_path = os.path.join(os.path.dirname(user_data_file), user["file_public_key_path"])
        file_public_key_data = read_public_key(file_public_key_path)
        file_public_key_b64 = base64.b64encode(file_public_key_data).decode('utf-8')
        cursor.execute(
            """
            INSERT INTO user_credentials (
                username, verifier, salt, public_key, encryption_key, password_disabled
            ) VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (username) DO NOTHING;
            """,
            (
                user["username"],
                verifier,
                salt,
                public_key_b64,
                file_public_key_b64,
                user.get("password_disabled", False)
            )
        )
    conn.commit()
    print("Database populated with example users.")


# -------------------------------
# Authentication Functions
# -------------------------------

def issue_challenge_password(username):
    """Issue a password-based challenge (nonce) to the client."""
    cursor.execute("SELECT verifier, salt FROM user_credentials WHERE username = %s;", (username,))
    result = cursor.fetchone()
    if not result:
        print(f"User {username} not found for password challenge.")
        return None

    verifier, salt = result
    _, prime, gen = salt.split(':')
    server_session = SRPServerSession(SRPContext(username, prime=prime, generator=gen), verifier)
    server_public = server_session.public
    b = server_session.private

    # Send salt and public to the client
    challenge = salt + ':' + server_public

    # Update last challenge in the database (optional)
    cursor.execute("UPDATE user_credentials SET last_challenge = %s WHERE username = %s;",
                   (b, username))
    conn.commit()

    print(f"Password challenge for {username}: {challenge}")
    return challenge


def issue_challenge_key(username):
    """Issue a public-key-based challenge (nonce only)."""
    challenge = base64.b64encode(os.urandom(32)).decode()
    cursor.execute("UPDATE user_credentials SET last_challenge = %s WHERE username = %s;", (challenge, username))
    conn.commit()
    print(f"Key challenge for {username}: {challenge}")
    return challenge


def verify_response(username, client_public=None, signed_challenge_hex=None):
    """Verify the client's response using the stored credentials."""
    cursor.execute("SELECT verifier, salt, public_key, last_challenge FROM user_credentials WHERE username = %s;",
                   (username,))
    result = cursor.fetchone()
    if result:
        verifier, salt, public_key_b64, challenge = result
        # Verify using password
        if client_public and salt and verifier and challenge:
            client_public, proof = client_public.split(':')
            salt, prime, gen = salt.split(':')
            server_session = SRPServerSession(SRPContext(username, prime=prime, generator=gen), verifier,
                                              private=challenge)
            server_session.process(client_public, salt)
            if server_session.verify_proof(proof, base64=True):
                print("Authentication successful using password!")
                return True
            else:
                print("Authentication failed using password.")
                return False

        # Verify using public key
        if signed_challenge_hex and public_key_b64:
            public_key_data = base64.b64decode(public_key_b64)
            public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())
            signed_challenge = bytes.fromhex(signed_challenge_hex)

            try:
                public_key.verify(
                    signed_challenge,
                    challenge.encode(),
                    ECDSA(hashes.SHA256())
                )
                print("Authentication successful using public key!")
                return True
            except Exception as e:
                print("Authentication failed using public key.")
                return False

    print("User not found or missing credentials.")
    return False


# -------------------------------
# Main Script
# -------------------------------

def main():
    """Populate database and test authentication."""
    # Populate database with initial users
    populate_database(USER_DATA_PATH)

    # Test authentication for all users
    with open(USER_DATA_PATH, "r") as f:
        users = json.load(f)

    for user in users:
        username = user["username"]
        print(f"\nTesting user: {username}")
        is_authenticated = False
        # Authenticate using public key
        if "private_key_path" in user:
            challenge = issue_challenge_key(username)
            private_key_path = os.path.join(os.path.dirname(USER_DATA_PATH), user["private_key_path"])
            signed_challenge = sign_challenge(private_key_path, challenge)
            print(f"Signed challenge for {username}: {signed_challenge}")
            is_authenticated = verify_response(username, signed_challenge_hex=signed_challenge)

        # Authenticate using password
        if "password_path" in user and not user.get("password_disabled", False):
            challenge = issue_challenge_password(username)
            salt, prime, gen, server_public = challenge.split(':')

            password_path = os.path.join(os.path.dirname(USER_DATA_PATH), user["password_path"])
            with open(password_path, "r") as password_file:
                password = password_file.read().strip()

            session = SRPClientSession(SRPContext(username, password=password, prime=prime, generator=gen))
            session.process(server_public, salt)
            client_public, client_proof = session.public, session.key_proof_b64
            res = client_public + ':' + client_proof
            is_authenticated |= verify_response(username, client_public=res)

        print(f"Authentication for {username}: {'Success' if is_authenticated else 'Failure'}")


if __name__ == "__main__":
    main()
    cursor.close()
    conn.close()
