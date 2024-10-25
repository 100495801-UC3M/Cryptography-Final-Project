import random
import string
from flask_mail import Mail, Message

class MailManager:
    def __init__(self, from_addr, codes_db):
        self.from_addr = from_addr
        self.mail = Mail()
        self.codes_db = codes_db

    def send_password_change_email(self, recipient):
        characters = string.ascii_letters + string.digits  # Incluye letras (mayúsculas y minúsculas) y dígitos
        code = ''.join(random.choices(characters, k=6))  # Genera un código de 6 caracteres
        msg = Message("Cambio de contraseña.", sender=self.from_addr, recipients=recipient)
        msg.body = ("El código es: ", code, ". Dispone de 5 minutos para cambiar la contraseña.")

        #NOTA: EL CODIGO NO ESTÁ CIFRADO DE MOMENTO. IMPLEMENTAR FUNCION DE CIFRADO EN CODES

        code_id = self.codes_db.add_code("change password", code)
        self.mail.send(msg)
        return code_id