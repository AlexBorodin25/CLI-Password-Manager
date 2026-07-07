import base64
import os
import getpass
from pathlib import Path
import sqlite3

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DB_PATH = Path("passwords.db")
KDF_ITERATIONS = 600_000

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
            username TEXT PRIMARY KEY,
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
    return base64.urlsafe_b64encode(key)

def get_fernet(conn):
    master_password = getpass.getpass('Enter master password: ')
    salt = get_salt(conn)
    key = get_key(master_password, salt)
    return Fernet(key)

def add_password(conn):
    username = input("Enter username: ").strip()
    password = getpass.getpass('Enter password: ')

    if not username or not password:
        print("Invalid username or password")
        return

    fernet = get_fernet(conn)
    encrypted_password = fernet.encrypt(password.encode("utf-8"))

    conn.execute(
        """
        INSERT INTO passwords (username, encrypted_password)
        VALUES (?, ?)
        ON CONFLICT (username) DO UPDATE SET
            encrypted_password = excluded.encrypted_password
    """, (username, encrypted_password))

    conn.commit()
    print(f"Password saved for {username}.")

def get_password(conn):
    username = input("Enter username: ").strip()

    row = conn.execute(
        """
        SELECT encrypted_password FROM passwords WHERE username = ?
        """, (username,)
    ).fetchone()

    if not row:
        print(f"No Password found for {username}.")
        return

    encrypted_password = row[0]
    fernet = get_fernet(conn)

    try:
        password = fernet.decrypt(encrypted_password).decode("utf-8")
    except InvalidToken:
        print("Could not decrypt password.")
        return

    print(f"Username: {username}")
    print(f"Password: {password}")


def delete_password(conn):
    username = input("Enter username: ").strip()

    cursor = conn.execute(
        """DELETE FROM passwords WHERE username = ?""",
        (username,)
    )
    conn.commit()

    if cursor.rowcount:
        print(f"Password deleted for {username}.")
    else:
        print(f"No password found for {username}.")

def list_usernames(conn):
    rows = conn.execute(
        """SELECT username FROM passwords ORDER BY username"""
    ).fetchall()

    if not rows:
        print("No passwords found.")
        return

    print("Usernames:")
    for row in rows:
        print(f" - {row[0]}")

def menu():
    print("Welcome to Password Manager")
    print("1: Add or update password")
    print("2: View Password")
    print("3: Delete Password")
    print("4: View stored Usernames")
    print("5: Exit")

def main():
    conn = connect_db()

    try:
        while True:
            menu()
            choice = input("Enter your choice: ").strip()

            if choice == "1":
                add_password(conn)
            elif choice == "2":
                get_password(conn)
            elif choice == "3":
                delete_password(conn)
            elif choice == "4":
                list_usernames(conn)
            elif choice == "5":
                print("Goodbye!")
                break
            else:
                print("Invalid choice.")

    finally:
        conn.close()

if __name__ == "__main__":
    main()