import sqlite3


class Users:
    def __init__(self, db_name="./db/users.db"):
        self.connection = sqlite3.connect(db_name, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        # Crea la tabla de users si no existe
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT DEFAULT "client",
                salt TEXT NOT NULL,
                public_key TEXT,
                private_key TEXT)''')
        self.connection.commit()

    def add_user(self, username, email, password, salt, public_key, private_key):
        # Añadir nuevo usuario a la base de datos
        username, email = username.lower(), email.lower()
        try:
            self.cursor.execute(
                "INSERT INTO users (username, email, password, salt, public_key, private_key) VALUES "
                "(?, ?, ?, ?, ?, ?)",
                (username, email, password, salt, public_key, private_key))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def check_user(self, username_or_email):
        # Buscar usuario por nombre de usuario o email
        user = self.cursor.execute(
            "SELECT * FROM users WHERE username=? OR email=?",
            (username_or_email, username_or_email)).fetchone()
        if user is None:
            return False
        return user

    def list_users(self):
        # Devolver lista de todos los usuarios
        return self.cursor.execute("SELECT * FROM users").fetchall()

    def update_password(self, username, password):
        # Cambiar la contraseña
        self.cursor.execute("UPDATE users SET password=? WHERE "
                            "username=?",   (password, username))
        self.connection.commit()

    def remove_user(self, username):
        # Eliminar Usuario
        self.cursor.execute("DELETE FROM users WHERE username=?", (username,))
        self.connection.commit()

