import os
import secrets

AES_KEY_SAVE_PATH = os.path.join(os.path.dirname(__file__), os.path.pardir, "aes_key")


def generate_aes_key():
    key = secrets.token_bytes(32)
    with open(AES_KEY_SAVE_PATH, "wb") as f:
        f.write(key)


if __name__ == "__main__":
    generate_aes_key()
