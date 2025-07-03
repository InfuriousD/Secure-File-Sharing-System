__all__ = ["get_db_connection", "close_db_connection"]

from flask import g
from psycopg2 import pool as psycopg2_pool

from config import SERVER_CONFIG

CONN_POOL = psycopg2_pool.SimpleConnectionPool(
    minconn=1,
    maxconn=10,
    dbname=SERVER_CONFIG.db_dbname,
    user=SERVER_CONFIG.db_user,
    password=SERVER_CONFIG.db_password,
    host=SERVER_CONFIG.db_host,
)


def get_db_connection():
    if "db_conn" not in g:
        g.db_conn = CONN_POOL.getconn()

    return g.db_conn


def close_db_connection(e=None):
    db_conn = g.pop("db_conn", None)

    if db_conn is not None:
        CONN_POOL.putconn(db_conn)
