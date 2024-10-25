# mail.py
import random
import string
from flask_mail import Mail, Message

class MailManager:
    def __init__(self, from_addr, codes_db, config):
        self.from_addr = from_addr
        self.mail = Mail()  # La inicialización de Mail se hace en main.py
        self.codes_db = codes_db
        self.config = config

    def send_password_change_email(self, recipient, expiration_date=None):
        characters = string.ascii_letters + string.digits
        code = ''.join(random.choices(characters, k=6))
        msg = Message("Cambio de contraseña.", sender=self.from_addr, recipients=recipient)
        msg.body = f"El código es: {code}. Dispone de 5 minutos para cambiar la contraseña."
        code_id = self.codes_db.add_code("change password", code, expiration_date)
        try:
            self.mail.send(msg)
            return code_id
        except Exception as excep:
            return f"Error al enviar el correo: {excep}"
