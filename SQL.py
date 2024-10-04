import sqlite3
import random

class SQL:
    def __init__(self):


    def add(self, user, password):
        password, salt = change_password(password)
        sql.append(user, password, salt)

    def change_password(self, password):
        salt_lenght = 25 - len(password)
        salt = random.randbytes(salt_lenght)
        password.append(salt)
        return password, salt

    def check(self, user, password):
        if user not in table:
            return False
        elif cifrado(password) != table[user][password]:
            return False
        else:
            return True