import sqlite3
import os
import logging
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class Codes:
    def __init__(self, db_name="codes.db"):
        self.connection = sqlite3.connect(db_name, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        # Crea la tabla de users si no existe
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                salt TEXT NOT NULL)''')
        self.connection.commit()

    def add_code(self, type, value):
        salt = self.generate_salt()
        self.hash_code(value, salt)
        self.cursor.execute(
            "INSERT INTO codes (type, value) VALUES "
            "(?,?, ?)",
            (type, value, salt))
        self.connection.commit()
        last_id = self.cursorlastrowid
        return last_id

    def generate_salt(self):
        return os.urandom(16)

    def hash_code(self, code, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                         iterations=100000, backend=default_backend())
        code_hash = base64.urlsafe_b64encode(kdf.derive(code.encode()))
        logging.info(f"Algoritmo: PBKDF2-HMAC-SHA256, Longitud de clave: 32 "
                     f"bytes, Salt: {base64.urlsafe_b64encode(salt)}, "
                     f"Contraseña_Hash: {code_hash}")
        return code_hash

    def compare_code_from_id(self, code, id):
        registered_code = self.cursor.execute("SELECT value, salt FROM codes WHERE "
                            "id=?",   (id)).fetchall()
        provided_code = self.hash_code(code, registered_code[1])
        if provided_code == registered_code:
            return True
        else:
            return False

    def remove_from_id(self, code_id):
        self.cursor.execute(
            "DELETE FROM codes WHERE id=?", code_id)

        self.connection.commit()