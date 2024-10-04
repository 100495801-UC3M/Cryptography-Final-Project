
#crear table, objeto que está en SQL
choice = input("Quieres registrate (pulsa 1) o iniciar sesión (pulsa cualquier otro botón)\n")
if choice == 1:
    user = input("Inserte el nombre de usuario\n")
    while user in table:
        user = input("Este nombre de usuario ya está siendo usado.\n")
    password = input("Inserte una contraseña para el usuario\n")
    while not password_verify(password):
        password = input("Esta contraseña no es aceptable. La longitud mínima es de 6 letras. Use mayúsculas, minúsculas y números.\n")
    email = input("Inserte un correo eléctronico para asociar tu cuenta con tu usuario\n")
    if email not in table:
        send_email(email)
    else:
        email == False
    while not send_email and email:
        email = input("El correo eléctronico que ha introducido es erróneo. Por favor, inténtelo de nuevo\n")
        send_email(email)
    table.add(user, password, email)

else choice == 2:
    user = input("Escribe tu nombre de usuario\n")
    password = input("Escribe la contraseña\n")
    while not table.check(user, password):
        print ("Nombre de usuario y contraseña incorrectos. Inténtelo de nuevo\n")
        if input("¿Se te ha olvidado la contraseña? Pulsa 1 para cambiarla o cualquiér otro botón para continuar\n") == 1:

        else:


def password_verify(password):
    if:
        return True
    else:
        return False