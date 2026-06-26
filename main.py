import base64
import os
import getpass
from pathlib import path
import sqlite3

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DB_PATH = Path("passwords.db")
KDF_ITERATIONS = 600,000

def connect_db():
    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            service TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            encrypted_password BLOB NOT NULL
        )
    """)

    conn.commit()
    return conn

def get_salt(conn):
    row = conn.execute(
        "SELECT value FROM metadata WHERE key = ?",
        ("salt",)
    ).fetchone()

    if row:
        return row[0]

    salt = os.urandom(16)
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES (?, ?)",
        ("salt", salt)
    )
    conn.commit()
    return salt

def get_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations = KDF_ITERATIONS
    )

    key = kdf.derive(master_password.encode("utf-8"))
    return base64.b64encode(key)

get_fernet(conn):
    master_password = getpass.getpass('Enter master password: ')
    salt = get_salt(conn)
    key = get_key(master_password, salt)
    return Fernet(key)

