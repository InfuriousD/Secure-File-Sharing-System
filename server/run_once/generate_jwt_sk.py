import os
import secrets

SK_SAVE_PATH = os.path.join(os.path.dirname(__file__), os.path.pardir, "jwt_sk")


def generate_jwt_sk():
    sk = secrets.token_urlsafe(32)
    with open(SK_SAVE_PATH, "w") as f:
        f.write(sk)


if __name__ == "__main__":
    generate_jwt_sk()
