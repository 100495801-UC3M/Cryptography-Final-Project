import os
import re
import logging
import base64
from mail import MailManager
from users import Users
from messages import Messages
from flask import (Flask, render_template, request, redirect, url_for,
                   session, abort)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
users_db = Users()
messages_db = Messages()
mail = MailManager("admin@gmail.com")
# Firmamos la sesión para que no pueda ser modificada por el cliente
app.secret_key = os.urandom(24)

route = "/"
@app.route(route)
def index():
    return render_template("index.html")


route = re.sub(r'^(\/).*', r'\1register', route)
@app.route(route, methods=["GET", "POST"])
def register():
    if "username" in session:
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        password2 = request.form["password2"]
        if not check_password(password):
            error = ("La contraseña es inválida. Debe tener al menos 6 "
                     "caracteres, una mayúscula, una minúscula, un número y "
                     "un carácter especial ($!%*?&_¿@#=-). No puede incluir "
                     "espacios.")
            return render_template("register.html", error=error)
        if password != password2:
            error = "Las contraseñas no coinciden"
            return render_template("register.html", error=error)
        salt = generate_salt()
        hashed_password = hash_password(password, salt)


        # result = users_db.add_admin(username, email, hashed_password, "admin",
        #                       base64.urlsafe_b64encode(salt))
        result = users_db.add(username, email, hashed_password, base64.urlsafe_b64encode(salt))


        if result:
            return redirect(url_for("login"))
        else:
            error = "Usuario o email ya registrados"
            return render_template("register.html", error=error)
    return render_template("register.html")


def check_password(password):
    if " " in password:
        return False

    if len(password) < 6:
        return False

    # Expresión regular para verificar las reglas
    if (re.search(r'[A-Z]', password) and  # Al menos una letra mayúscula
            re.search(r'[a-z]', password) and  # Al menos una letra minúscula
            re.search(r'\d', password, re.ASCII) and  # Al menos un número
            re.search(r'[$!%*?&_¿@#=-]',
                      password)):  # Al menos un carácter especial (puedes personalizar los caracteres especiales)
        return True
    else:
        return False


route = re.sub(r'^(\/).*', r'\1login', route)
@app.route(route, methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("home"))
    if request.method == "POST" and request.path == "/home/change-password-email":
        return redirect(url_for("change_password_email"))
    elif request.method == "POST":
        username_or_email = request.form["username_or_email"].lower()
        password = request.form["password"]
        user = users_db.check_user(username_or_email)
        if user is not None:
            stored_password = user["password"]
            salt = base64.urlsafe_b64decode(user["salt"])
            if verify_password(stored_password, salt, password):
                session["username"] = username_or_email
                return redirect(url_for('home'))
            else:
                error = "Usuario o contraseña incorrectos"
                return render_template("login.html", error=error)
    return render_template("login.html")

route = re.sub(r'^(\/).*', r'\1change-password-email', route)
@app.route(route, methods=["GET", "POST"])
def change_password_email():
    if request.method == "POST":
        # Aquí debemos verificar si el formulario se envía correctamente
        username_or_email = request.form.get("username_or_email")
        if username_or_email is None:
            error = "El campo 'Nombre de Usuario o Email' es obligatorio."
            return render_template("change-password-email.html", error=error)

        # Convertir a minúsculas solo si no es None
        username_or_email = username_or_email.lower()
        username_or_email = users_db.get_email_from_user(username_or_email)
        if username_or_email == False:
            error = ("El usuario o correo no está registrado en la página web")
            return render_template("change-password-email.html", error=error)
        else:
            mail.send_password_change_email(username_or_email, url_for("change-password.html"))
    else:
        return render_template("change-password-email.html")

route = re.sub(r'^(\/).*', r'\1home', route)
@app.route(route, methods=["GET", "POST"])
def home():
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        if request.method == "POST" and request.path == "/home/change-password":
            return redirect(url_for("change-password.html"))
        user = users_db.check_user(session["username"])
        username = user["username"]
        role = user["role"]
    return render_template("home.html", username=username, role=role)


route = re.sub(r'^(\/home).*', r'\1/users', route)
@app.route(route, methods=["GET", "POST"])
def list_users():
    if "username" not in session:
        abort(404)
    user = users_db.check_user(session["username"])
    if user["role"] != "admin":
        abort(404)
    if request.method == "POST":
        user_id = request.form.get("id")
        users_db.remove_user(user_id)
        logging.info("El usuario se ha eliminado de la tabla de datos "
                     "correctamente.")
    users = users_db.list_users()
    return render_template("users.html", users=users)


route = re.sub(r'^(\/home).*', r'\1/change-password', route)
@app.route(route, methods=["GET", "POST"])
def change_password():
    user = users_db.check_user(session["username"])
    username = user["username"]
    role = user["role"]
    if request.method == "POST":
        password = request.form["password"]
        new_password = request.form["new_password"]
        new_password2 = request.form["new_password2"]
        user = users_db.check_user(username)
        stored_password = user["password"]
        salt = base64.urlsafe_b64decode(user["salt"])
        if not verify_password(stored_password, salt, password):
            error = "La contraseña no es correcta"
            return render_template("change-password.html", username=username,
                                   role=role, error=error)
        if not check_password(new_password):
            error = ("La contraseña es inválida. Debe tener al menos 6 "
                     "caracteres, una mayúscula, una minúscula, un número y "
                     "un carácter especial ($!%*?&_¿@#=-). No puede incluir "
                     "espacios.")
            return render_template("change-password.html", username=username,
                                   role=role, error=error)
        if new_password != new_password2:
            error = "Las contraseñas no coinciden"
            return render_template("change-password.html", username=username,
                                   role=role, error=error)
        hashed_password = hash_password(new_password, salt)
        users_db.update_password(username, hashed_password)
        return render_template("home.html", username=username, role=role)
    else:
        return render_template("change-password.html")

route = re.sub(r'^(\/home).*', r'\1/messages', route)
@app.route(route, methods=["GET", "POST"])
def send_message():
    # Si es un POST, procesamos el envío de mensajes
    if request.method == 'POST':
        sender = session.get('username')
        recipient = request.form.get('recipient')
        content = request.form.get('message')

        # Guardar el mensaje en la base de datos
        messages_db.send_message(sender, recipient, content)
        return redirect(url_for("send_message"))

    # Si es un GET, mostramos las últimas conversaciones
    # Aquí se pueden cargar las últimas conversaciones
    username = session.get('username')
    conversations = get_last_conversations(username)
    return render_template('messages.html', conversations=conversations)

def get_last_conversations(username):
    return messages_db.conversations(username)



route = re.sub(r'^(\/).*', r'\1/logout', route)
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


def generate_salt():
    return os.urandom(16)


def hash_password(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,
                     iterations=100000, backend=default_backend())
    password_hash = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    logging.info(f"Algoritmo: PBKDF2-HMAC-SHA256, Longitud de clave: 32 "
                 f"bytes, Salt: {base64.urlsafe_b64encode(salt)}, "
                 f"Contraseña_Hash: {password_hash}")
    return password_hash

def verify_password(stored_password, salt, provided_password):
    provided_password_hash = hash_password(provided_password, salt)
    return provided_password_hash == stored_password


if __name__ == "__main__":
    app.run(debug=True)

