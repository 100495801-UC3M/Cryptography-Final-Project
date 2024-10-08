import sqlite3


class SQL:
    def __init__(self, db_name="users.db"):
        self.connection = sqlite3.connect(db_name, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        # Crea la tabla de usuarios si no existe
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT "user"
            )
        ''')
        self.connection.commit()

    def add(self, username, email, password):
        # Añadir nuevo usuario a la base de datos
        username, email = username.lower(), email.lower()
        self.cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, password))
        self.connection.commit()

    def check_user(self, username_or_email, password):
        # Buscar usuario por nombre de usuario o email
        user = self.cursor.execute(
            "SELECT * FROM users WHERE username=? OR email=?",
            (username_or_email, username_or_email)).fetchone()
        if user:
            stored_password = user["password"]
            if stored_password == password:
                return True
        return False

    def close(self):
        self.connection.close()
