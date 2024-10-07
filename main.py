
#crear table, objeto que está en SQL
#test
array = {"user": "a", "password": "3", "email": "x@y"}
running = True
while running:
    choice = input("Quieres registrate (pulsa 1) o iniciar sesión (pulsa cualquier otro botón)\n")
    if choice == "1":
        user = input("Inserte el nombre de usuario\n")
        #while not user_verify(user):
            #user = input("Usuario erróneo. La longitud mínima es de 3 carácteres.")
            #while user in array["user"]:
            #while user in table:
            #    user = input("Este nombre de usuario ya está siendo usado. Inserte uno nuevo.\n")
        #para la contraseña ver si se puede escribir en oculto
        password, password2 = 0, 1
        while password != password2:
            password = input("Inserte una contraseña para el usuario\n")
            #while not password_verify(password):
            #    password = input("Esta contraseña no es aceptable. La longitud mínima es de 6 carácteres. "
            #                     "Use mayúsculas, minúsculas y números. No está permitido usar el @.\n")
            password2 = input("Introduce la contraseña de nuevo\n")
            if password != password2:
                print("Las contraseñas no coinciden.")
        stop_loop1 = False
        while not stop_loop1:
            email = input("Inserte un correo eléctronico para asociarlo con tu usuario.\n")
            #if email in table[email]:
            if email in array["email"]:
                email = input("El correo eléctronico ya está registrado. Presiona 1 para volver a la página principal.\n")
                if email == "1":
                    stop_loop1 = True
            # mirar si existe el correo eléctronico y comprobar que pueda verificar que el correo eléctronico quiere
            # registrarse a esta aplicación. Si no se puede comprobar, eliminar este else.
            #else:
            #    if send_registration_email(email) == False:
            #        print("El correo eléctronico no existe.\n")
            #table.add(user, password, email)
            print("El usuario ha sido registrado con exito.")

    else:
        user = input("Escribe tu nombre de usuario o correo electrónico\n")
        stop_loop1 = False
        while not stop_loop1:
            password = input("Escribe la contraseña\n")
            # if table.check(user, password) == False:
            if (array["user"] != user or array["email"] != user) and array["password"] != password:
                print("\nNombre de usuario y contraseña incorrectos. Inténtelo de nuevo")
                choice_user = input(
                    "¿Se te ha olvidado la contraseña? Pulsa 1 para cambiarla. ¿Eres nuevo? Pulsa 2 para volver"
                    " al inicio y registrarte o introduce el usuario y luego la contraseña de nuevo\n")
                if choice_user == "1":
                    user = input("Introduce el nombre de usuario o el correo eléctronico asociado con su cuenta.\n")
                    stop_loop2 = False
                    #while (user not in table[user] and user not in table[email]) and not stop_loop2:
                    while (array["user"] != user and array["email"] != user) and not stop_loop2:
                        user = input("Usuario o email no registrado. Intentelo de nuevo o pulse 1 para volver al menú principal.\n")
                        if user == "1":
                            stop_loop2 = True
                    if not stop_loop2:
                        password = input("Introduce la nueva contraseña.\n")
                        while input("Introduce la contraseña de nuevo.\n") != password:
                            password = input("Las contraseñas no coinciden. Introduce la nueva contraseña.\n")
                        # if "@" not in user:
                        #    user = table.get_email_from_user(user)
                        # send_change_password_email(user)
                        # table.change_password(email, password)
                        array["password"] = password
                elif choice_user == "2":
                    stop_loop1 = True
                else:
                    user = choice_user
        if stop_loop1 == False:
            #if "@" in user:
            #    table.get_user_from_email(email)
            print("Bienvenido", user)
    user, password, password2, email = 0, 0, 0, 0

    """def password_verify(password):
        if:
            return True
        else:
            return False"""

    """def user_verify(user):
        if:
            return True
        else:
             return False"""

    """def send_registration_email(email)
        """

    """def send_change_password_email(email)
        """