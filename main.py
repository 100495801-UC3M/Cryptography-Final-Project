import os
from flask import (Flask, render_template, request, redirect, url_for,
                   session, abort)
from SQL import SQL

app = Flask(__name__)
db = SQL()
# Firmamos la sesión para que no pueda ser modificada por el cliente
app.secret_key = os.urandom(24)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        db.add(username, email, password)
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
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


@app.route("/users")
def listar_usuarios():
    if "username" not in session:
        abort(404)
    user = db.cursor.execute("SELECT role FROM users WHERE username=?",
                             (session["username"],)).fetchone()
    if not user:
        user = db.cursor.execute("SELECT role FROM users WHERE email=?",
                                 (session["username"],)).fetchone()
    if user["role"] != "admin":
        abort(404)
    usuarios = db.cursor.execute(
        "SELECT id, username, email, password FROM users").fetchall()
    return render_template("users.html", usuarios=usuarios)


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
