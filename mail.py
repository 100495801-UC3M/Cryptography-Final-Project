from flask_mail import Mail, Message

class MailManager:
    def __init__(self, from_addr):
        self.from_addr = from_addr
        self.mail = Mail()

    def send_password_change_email(self, recipient, url):
        msg = Message("Cambio de contraseña.", sender=self.from_addr, recipients=recipient)
        msg.body = ("Para cambiar la contraseña, entre en el siguiente link: ", url)
        self.mail.send(msg)