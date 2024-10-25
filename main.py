import os
import re
import base64
import logging
from datetime import datetime, timedelta
from mail import MailManager
from users import Users
from messages import Messages
from codes import Codes
from flask import (Flask, render_template, request, redirect, url_for,
                   session, abort)

app = Flask(__name__)
codes_db = Codes()
users_db = Users()
messages_db = Messages()
mail = MailManager("admin@gmail.com", codes_db)
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
        salt = codes_db.generate_salt()
        hashed_password = codes_db.hash_code(password, salt)


        # result = users_db.add_admin(username, email, hashed_password, "admin",
        #                       base64.urlsafe_b64encode(salt))
        result = users_db.add(username, email, hashed_password, base64.urlsafe_b64encode(salt))


        if result:
            return redirect(url_for("login"))
        else:
            error = "Usuario o email ya registrados"
            return render_template("register.html", error=error)
    return render_template("register.html")


route = re.sub(r'^(\/).*', r'\1login', route)
@app.route(route, methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("home"))
    if request.method == "POST":
        if request.form.get("form_id") == "loginForm":
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
        else:
            email = request.form["email"]
            code_id = mail.send_password_change_email(email)
            expiration_date = datetime.now() + timedelta(minutes=5)
            while datetime.now() <= expiration_date:
                code = request.form["code"]
                if codes_db.compare_code_from_id(code, code_id):
                    """Implementar función para cambiar contraseña"""
                    return redirect(url_for("login"))
            codes_db.remove_from_id(code_id)
            return redirect(url_for("login"))

    else:
        return render_template("login.html")


route = re.sub(r'^(\/).*', r'\1home', route)
@app.route(route, methods=["GET", "POST"])
def home():
    if "username" not in session:
        return redirect(url_for("login"))
    
    user = users_db.check_user(session["username"])
    username = user["username"]
    role = user["role"]
    

    if request.method == "POST":
        if "search_form" in request.form:
            user_searched_input = request.form["user_searched"]
            user_searched_data = users_db.check_user(user_searched_input)
            if user_searched_data:
                session['found'] = True
                session['user_searched'] = user_searched_data["username"]
                session["conversations"] = messages_db.conversations(username, session['user_searched'])
            else:
                session['found'] = False
                error = "Usuario no encontrado"
                return render_template("home.html", role=role, error=error)
            
            return redirect(url_for("home"))

        elif "send_message" in request.form:
            message = request.form["message"]
            user_searched = session.get("user_searched")
            if user_searched:
                if messages_db.send_message(username, user_searched, message):
                    session["conversations"] = messages_db.conversations(username, user_searched)
                else:
                    error = "Error al enviar el mensaje"
                    return render_template("home.html", role=role, error=error)
            else:
                error = "No hay un usuario buscado para enviar el mensaje"
                return render_template("home.html", role=role, error=error)
            
            return redirect(url_for("home"))

    username = user["username"]
    user_searched = session.get("user_searched")
    conversations = session.get("conversations")
    found = session.get("found")
    print(username)
    print(user_searched)
    return render_template("home.html", username=username, role=role, conversations=conversations, found=found, user_searched=user_searched)


route = re.sub(r'^(\/).*', r'\1users', route)
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


route = re.sub(r'^(\/).*', r'\1/profile', route)
@app.route(route, methods=["GET", "POST"])
def profile():
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        user = users_db.check_user(session["username"])
        username = user["username"]
        role = user["role"]

        if request.method == "POST":
            password = request.form["password"]
            new_password = request.form["new_password"]
            new_password2 = request.form["new_password2"]
            stored_password = user["password"]
            salt = base64.urlsafe_b64decode(user["salt"])
            if not verify_password(stored_password, salt, password):
                error = "La contraseña no es correcta"
                return render_template("profile.html", username=username, role=role, error=error)
            if not check_password(new_password):
                error = ("La contraseña es inválida. Debe tener al menos 6 "
                        "caracteres, una mayúscula, una minúscula, un número y "
                        "un carácter especial ($!%*?&_¿@#=-). No puede incluir "
                        "espacios.")
                return render_template("perfil.html", username=username,
                                    role=role, error=error)
            if new_password != new_password2:
                error = "Las contraseñas no coinciden"
                return render_template("profile.html", username=username,
                                    role=role, error=error)
            hashed_password = codes_db.hash_code(new_password, salt)
            users_db.update_password(username, hashed_password)
            success = "Las contraseña ha sido actualizada correctamente"
            return render_template("profile.html", username=username, role=role, success=success)
        return render_template("profile.html", username=username, role=role)


route = re.sub(r'^(\/).*', r'\1/logout', route)
@app.route("/logout", methods=["GET", "POST"])
def logout():
    if request.method == "GET":
        abort(404)
    else:
        session.clear()
        return redirect(url_for("index"))



def check_password(password):
    if " " in password:
        return False

    if len(password) < 6:
        return False

    if (re.search(r'[A-Z]', password) and  # Al menos una letra mayúscula
            re.search(r'[a-z]', password) and  # Al menos una letra minúscula
            re.search(r'\d', password, re.ASCII) and  # Al menos un número
            re.search(r'[$!%*?&_¿@#=-]', password)):  # Al menos un carácter especial (puedes personalizar los caracteres especiales)
        return True
    else:
        return False


def verify_password(stored_password, salt, provided_password):
    provided_password_hash = codes_db.hash_code(provided_password, salt)
    return provided_password_hash == stored_password


if __name__ == "__main__":
    app.run(debug=True)

