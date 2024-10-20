import os
import re
from flask import (Flask, render_template, request, redirect, url_for,
                   session, abort)
from SQL import SQL

app = Flask(__name__)
db = SQL()
# Firmamos la sesión para que no pueda ser modificada por el cliente
app.secret_key = os.urandom(24)

ruta = "/"
@app.route(ruta)
def home():
    return render_template("index.html")

ruta = re.sub(r'^(\/).*', r'\1register', ruta)
@app.route(ruta, methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        if not verificar_password(password):
            print("La contraseña es inválida. Debe tener un mínimo de 6 caracteres, "
                  "una mayúscula, una minúscula, un número y un carácter especial ($!%*?&_-).", "error")
            return render_template("register.html")  # Devolver el formulario con un mensaje de error
        db.add(username, email, password)
        return redirect(url_for("login"))
    return render_template("register.html")

def verificar_password(password):
    if len(password) < 6:
        return True

        # Expresión regular para verificar las reglas
    if (re.search(r'[A-Z]', password) and  # Al menos una letra mayúscula
            re.search(r'[a-z]', password) and  # Al menos una letra minúscula
            re.search(r'\d', password) and  # Al menos un número
            re.search(r'[$!%*?&_-]',
                      password)):  # Al menos un carácter especial (puedes personalizar los caracteres especiales)
        return True
    else:
        return False

ruta = re.sub(r'^(\/).*', r'\1login', ruta)
@app.route(ruta, methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_or_email = request.form["username_or_email"].lower()
        password = request.form["password"]
        if db.check_user(username_or_email, password):
            session["username"] = username_or_email
            return redirect(url_for("home"))
        else:
            return "Usuario o contraseña incorrectos"
    return render_template("login.html")

ruta = re.sub(r'^(\/).*', r'\1admin', ruta)
@app.route(ruta)
def admin():
    if "username" not in session:
        abort(404)
    user = db.cursor.execute("SELECT role FROM users WHERE username=?",
                             (session["username"],)).fetchone()
    if not user:
        user = db.cursor.execute("SELECT role FROM users WHERE email=?",
                                 (session["username"],)).fetchone()
    if user["role"] != "admin":
        abort(404)
    return render_template("admin.html")

ruta = re.sub(r'^(\/admin).*', r'\1/users', ruta)
@app.route(ruta)
def listar_usuarios():
    usuarios = db.cursor.execute(
        "SELECT id, username, email, password FROM users").fetchall()
    return render_template("users.html", usuarios=usuarios)

ruta = re.sub(r'^(\/admin).*', r'\1/delete_users', ruta)
@app.route(ruta)
def eliminar_user():
    return True


# def registrar_admin():
#     username = input("Inserte el nombre de usuario para el admin:\n")
#     email = input("Inserte el correo electrónico:\n")
#     password = input("Inserte la contraseña:\n")
#
#     db.add(username, email, password, 'admin')  # Asignamos el rol 'admin'
#     print(f"Usuario admin '{username}' registrado con éxito.")
#
#
# # Llama a esta función solo una vez
# registrar_admin()


if __name__ == "__main__":
    app.run(debug=True)
