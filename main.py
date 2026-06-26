import base64
import os
import getpass
from pathlib import path
import sqlite3

from cryptography.fernet import Fernet


DB_PATH = Path("passwords.db")

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

