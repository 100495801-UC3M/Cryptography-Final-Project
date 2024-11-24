import os
import re
import base64
import logging
from datetime import timedelta
import app.security as security
from app.users import Users
from app.messages import Messages
from flask import Flask, render_template, request, redirect, url_for, session, abort


# Iniciamos el servidor flask
app = Flask(__name__)

# Firmamos la sesión para que no pueda ser modificada por el cliente
app.secret_key = os.urandom(24)

# Límite de sesión de 5 minutos
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=5)

# Inicializamos las bases de datos
users_db = Users()
messages_db = Messages()

# Configuración logging para que se muestre en la consola
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


route = "/"
@app.route(route)
def index():
    return render_template("index.html")


route = re.sub(r"^(\/).*", r"\1register", route)
@app.route(route, methods=["GET", "POST"])
def register():
    if "username" in session:
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        password2 = request.form["password2"]
        if not security.check_password(password):
            error = ("La contraseña es inválida. Debe tener al menos 6 "
                     "caracteres, una mayúscula, una minúscula, un número y "
                     "un carácter especial ($!%*?&_¿@#=-). No puede incluir "
                     "espacios.")
            return render_template("register.html", error=error)
        if password != password2:
            error = "Las contraseñas no coinciden"
            return render_template("register.html", error=error)
        
        salt = security.generate_salt_aes("salt", 16)
        hashed_password = security.hash(password, salt)

        private_key, public_key = security.generate_keys()

        private_key = security.encrypt_private_key(private_key, password, salt)

        # TODO quitar esta linea cuando se termine la entrega
        public_key = security.serialize_public_key(public_key)

        public_key = security.create_petition(public_key)
        # TODO agregar funcion aqui para que se informe al usuario que se esta procesando la peticion


        result = users_db.add_user(username, email, hashed_password, base64.urlsafe_b64encode(salt), public_key, private_key)


        if result:
            logging.info(f"Usuario {username} registrado exitosamente.")
            return redirect(url_for("login"))
        else:
            logging.error(f"Error en el registro de {username}. El usuario o el email ya están registrados.")
            error = "Usuario o email ya registrados"
            return render_template("register.html", error=error)
    return render_template("register.html")


route = re.sub(r"^(\/).*", r"\1login", route)
@app.route(route, methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("home"))
    if request.method == "POST":
        if request.form.get("form_id") == "loginForm":
            username_or_email = request.form["username_or_email"].lower()
            password = request.form["password"]
            user = users_db.check_user(username_or_email)
            if user is not False:
                stored_password = user["password"]
                salt = base64.urlsafe_b64decode(user["salt"])
                if security.verify_password(stored_password, salt, password):
                    session["username"] = user["username"]
                    session["role"] = user["role"]
                    private_key = security.decrypt_private_key(user["private_key"], password, salt)
                    private_key = security.serialize_private_key(private_key)

                    # TODO no se si esta linea está bien o si es necesaria si quiera
                    session["public_key"] = security.get_public_key(user["public_key"])

                    session["private_key"] = private_key
                    session.permanent = True
                    logging.info(f"Usuario {username_or_email} ha iniciado sesión.")
                    return redirect(url_for("home"))
                else:
                    logging.error(f"Intento fallido de inicio de sesión para {username_or_email}.")
                    error = "Usuario o contraseña incorrectos o la cuenta no existe"
                    return render_template("login.html", error=error)
            else:
                logging.error(f"Intento fallido de inicio de sesión para {username_or_email}.")
                error = "Usuario o contraseña incorrectos o la cuenta no existe"
                return render_template("login.html", error=error)
    else:
        return render_template("login.html")


route = re.sub(r"^(\/).*", r"\1home", route)
@app.route(route, methods=["GET", "POST"])
def home():
    if "username" not in session:
        return redirect(url_for("login"))   

    if request.method == "POST":
        if "search_form" in request.form:
            user_searched_input = request.form["user_searched"]
            user_searched_data = users_db.check_user(user_searched_input)
            if user_searched_data:
                session["found"] = True
                session["user_searched"] = user_searched_data["username"]
                conversations = messages_db.conversations(session["username"], session["user_searched"])
                private_key = security.deserialize_private_key(session["private_key"])

                # TODO no se si esta linea está bien o si es necesaria si quiera
                session["public_key"] = security.get_public_key(session["public_key"])

                good_messages = security.check_messages(conversations, session["username"], private_key)
                session["conversations"] = good_messages
            else:
                session["found"] = False
                error = "Usuario no encontrado"
                return render_template("home.html", role=session["role"], error=error)
            
            return redirect(url_for("home"))

        elif "send_message" in request.form:
            message = request.form["message"]
            user_searched = session.get("user_searched")
            if user_searched:
                receiver = users_db.check_user(user_searched)
                #TODO quitar la primera linea y luego cambiar receiver_public_key por receiver["public_key"]
                receiver_public_key = security.deserialize_public_key(receiver["public_key"])
                receiver_public_key = security.get_public_key(receiver_public_key)

                sender = users_db.check_user(session["username"])
                #TODO quitar la primera linea y luego cambiar receiver_public_key por sender["public_key"]
                sender_public_key = security.deserialize_public_key(sender["public_key"])
                sender_public_key = security.get_public_key(sender_public_key)

                aes_key = security.generate_salt_aes("aes", 32)
                encrypted_message = security.encrypt_aes_message(message, aes_key)
                hmac = security.generate_hmac(aes_key, encrypted_message)
                encrypted_aes_key_sender = security.encrypt_aes_rsa_key(aes_key, sender_public_key)
                encrypted_aes_key_receiver = security.encrypt_aes_rsa_key(aes_key, receiver_public_key)
                if messages_db.send_message(session["username"], user_searched, encrypted_message, hmac, encrypted_aes_key_sender, encrypted_aes_key_receiver):
                    conversations = messages_db.conversations(session["username"], user_searched)
                    private_key = security.deserialize_private_key(session["private_key"])
                    good_messages = security.check_messages(conversations, session["username"], private_key)
                    session["conversations"] = good_messages
                else:
                    error = "Error al enviar el mensaje"
                    return render_template("home.html", role=session["role"], error=error)
            else:
                error = "No hay un usuario buscado para enviar el mensaje"
                return render_template("home.html", role=session["role"], error=error)
            
            return redirect(url_for("home"))

    if session.get("user_searched") is not None:
        conversations = messages_db.conversations(session["username"], session.get("user_searched"))
        private_key = security.deserialize_private_key(session["private_key"])
        good_messages = security.check_messages(conversations, session["username"], private_key)
        session["conversations"] = good_messages

    user_searched = session.get("user_searched")
    conversations = session.get("conversations")
    found = session.get("found")
    return render_template("home.html", username=session["username"], role=session["role"], conversations=conversations, found=found, user_searched=user_searched)


route = re.sub(r"^(\/).*", r"\1users", route)
@app.route(route, methods=["GET", "POST"])
def list_users():
    if "username" not in session:
        abort(404)
    if session["role"] != "admin":
        abort(404)
    if request.method == "POST" and "delete" in request.form:
        user_deleted = request.form.get("username")
        messages_db.remove_messages(user_deleted)
        users_db.remove_user(user_deleted)
        logging.info("El usuario se ha eliminado de la tabla de datos correctamente.")

    if request.method == "POST" and "promote" in request.form:
        user_promoted = request.form.get("username")
        users_db.promote_user(user_promoted)
    users = users_db.list_users()
    return render_template("users.html", users=users)


route = re.sub(r"^(\/).*", r"\1messages", route)
@app.route(route, methods=["GET", "POST"])
def list_messages():
    if "username" not in session:
        abort(404)
    if session["role"] != "admin":
        abort(404)
    messages = messages_db.list_messages()
    messages_list = []
    for m in messages:
        messages_list.append(dict(m))
    if request.method == "POST":
        message_id = request.form.get("id")
        message = messages_db.get_message(message_id)
        private_key = security.deserialize_private_key(session["private_key"])
        message = security.check_messages(message, session["username"], private_key)
        if message != "error":
            for m in messages_list:
                if int(m["id"]) == int(message_id):
                    m["text"] = message[0][2]
        return render_template("messages.html", messages=messages_list)
    return render_template("messages.html", messages=messages_list)


route = re.sub(r"^(\/).*", r"\1/profile", route)
@app.route(route, methods=["GET", "POST"])
def profile():
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        user = users_db.check_user(session["username"])
        username = user["username"]
        if request.method == "POST" and "change_password" in request.form:
            password = request.form["password"]
            new_password = request.form["new_password"]
            new_password2 = request.form["new_password2"]
            stored_password = user["password"]
            salt = base64.urlsafe_b64decode(user["salt"])
            if not security.verify_password(stored_password, salt, password):
                error = "La contraseña no es correcta"
                return render_template("profile.html", username=username, error=error)
            if not security.check_password(new_password):
                error = ("La contraseña es inválida. Debe tener al menos 6 "
                        "caracteres, una mayúscula, una minúscula, un número y "
                        "un carácter especial ($!%*?&_¿@#=-). No puede incluir "
                        "espacios.")
                return render_template("profile.html", username=username, error=error)
            if new_password != new_password2:
                error = "Las contraseñas no coinciden"
                return render_template("profile.html", username=username, error=error)
            hashed_password = security.hash(new_password, salt)
            users_db.update_password(username, hashed_password)
            success = "Las contraseña ha sido actualizada correctamente"
            return render_template("profile.html", username=username, success=success)
        
        if request.method == "POST" and "delete_account" in request.form:
            messages_db.remove_messages(session["username"])
            users_db.remove_user(session["username"])
            session.clear()
            return redirect(url_for("index"))
        return render_template("profile.html", username=username)


route = re.sub(r"^(\/).*", r"\1/logout", route)
@app.route("/logout", methods=["GET", "POST"])
def logout():
    if request.method == "GET":
        abort(404)
    else:
        session.clear()
        return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
