__all__ = ["SERVER_CONFIG"]

import json
import os
from dataclasses import dataclass

__FILE_DIR = os.path.dirname(os.path.abspath(__file__))

"""
{
  "host": "127.0.0.1",
  "port": 8888,
  "timeout": 60,  # seconds
  "max_expiration": 432000,  # seconds
  "max_file_size": 0,  # bytes, 0 means unlimited
  "jwt_sk_path": "jwt_sk",
  "aes_key_path": "aes_key",
  "max_renewal": 5,
  "db": {
    "dbname": "cnt5410project",
    "user": "cnt5410_mgr",
    "password": "strong_password",
    "host": "localhost"
  }
}
"""

"""
{
    "argon2_type": "Argon2id",
    "memory_cost_kb": 102400,
    "parallelism": 6,
    "time_cost": 45,
    "salt_length": 16,
    "hash_length": 32,
    "encoding": "utf-8"
}
"""


def _load_config():
    with open(os.path.join(__FILE_DIR, "server_config.json"), "r") as f:
        return json.load(f)


def _load_jwt_sk(sk_file_path):
    with open(sk_file_path, "r") as f:
        return f.read()


def _load_aes_key(key_file_path):
    with open(key_file_path, "rb") as f:
        return f.read()


@dataclass
class _Config:
    host: str
    port: int
    timeout: int
    max_expiration: int
    max_file_size: int
    jwt_sk: str
    aes_key: bytes
    max_renewal: int
    db_dbname: str
    db_user: str
    db_password: str
    db_host: str


_config_data = _load_config()

SERVER_CONFIG = _Config(
    host=_config_data["host"],
    port=_config_data["port"],
    timeout=_config_data["timeout"],
    max_expiration=_config_data["max_expiration"],
    max_file_size=_config_data["max_file_size"],
    jwt_sk=_load_jwt_sk(_config_data["jwt_sk_path"]),
    aes_key=_load_aes_key(_config_data["aes_key_path"]),
    max_renewal=_config_data["max_renewal"],
    db_dbname=_config_data["db"]["dbname"],
    db_user=_config_data["db"]["user"],
    db_password=_config_data["db"]["password"],
    db_host=_config_data["db"]["host"],
)
