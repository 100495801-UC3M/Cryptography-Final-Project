import sqlite3
from datetime import datetime

class Messages:
    def __init__(self, db_name="messages.db"):
        self.connection = sqlite3.connect(db_name, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        # Crea la tabla de users si no existe
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                text TEXT NOT NULL,
                datehour TEXT NOT NULL)''')
        self.connection.commit()

    def send_message(self, sender, receiver, text):
        try:
            date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.cursor.execute(
                "INSERT INTO messages (sender, receiver, text, datehour) VALUES "
                "(?, ?, ?, ?)",
                (sender, receiver, text, date))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def conversations(self, user):
        # Cargar los mensajes entre el usuario actual y el destinatario
        conversations = self.cursor.execute("SELECT * FROM messages WHERE sender = ? or receiver = ?"
                                            "ORDER BY datehour DESC",(user, user)).fetchall()
        if not conversations:
            return []

        # Añadir los últimos usuarios con los que se ha hablado en un dict. Se ordenarán de más nuevo a lo más viejo
        other_user = {}
        for msg in conversations:
            if msg[1] == user:
                colour = "blue"
                if msg[2] not in other_user:
                    other_user[msg[2]] = []
                other_user[msg[2]].append([msg[3], msg[4], colour])
            else:
                colour = "red"
                if msg[1] not in other_user:
                    other_user[msg[1]] = []
                other_user[msg[1]].append([msg[3], msg[4], colour])
        return other_user