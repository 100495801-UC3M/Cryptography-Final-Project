import os
import re
import logging
import base64

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

from .users import Users

def check_password(password):
    # Revisar si la contraseña cumple con los requisitos mínimos
    if " " in password:
        return False

    if len(password) < 6:
        return False

    if (re.search(r"[A-Z]", password) and  # Al menos una letra mayúscula
            re.search(r"[a-z]", password) and  # Al menos una letra minúscula
            re.search(r"\d", password, re.ASCII) and  # Al menos un número
            re.search(r"[$!%*?&_¿@#=-]", password)):  # Al menos un carácter especial
        return True
    else:
        return False


def generate_salt_aes(procces, number):
    # Generar salt o una clave aes
    key = os.urandom(number)
    if procces == "salt":
        logging.info(f"Salt generado: {key.hex()}, Longitud de clave: {number * 8} bits")
    else:
        logging.info(f"Salt generado: {key.hex()}, Longitud de clave: {number * 8} bits")
    return key


def hash(password, salt):
    # Hasear la contrasña usando el hash
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                        iterations=100000, backend=default_backend())
    password_hash = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    logging.info(f"Algoritmo: PBKDF2-HMAC-SHA256, Longitud de clave: 32 "
                    f"bytes, Salt: {base64.urlsafe_b64encode(salt)}, "
                    f"Contraseña_Hash: {password_hash}")
    return password_hash


def verify_password(stored_password, salt, provided_password):
    # Verificar si la contraseña introducida hasheada con el salt es igual a la guardada
    provided_password_hash = hash(provided_password, salt)
    return provided_password_hash == stored_password


def generate_keys():
    # Generar las clave privada y pública
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_private_key(private_key, password, salt):
    # Encriptar la clave privada
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    private_encrypted_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(key)
    )

    return private_encrypted_key


def serialize_private_key(private_key):
    # Serializar la clave privada
    serialized_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return serialized_private_key.decode("utf-8")


def serialize_public_key(public_key):
    # Serializar la clave pública
    return public_key.public_bytes(encoding = serialization.Encoding.PEM,
    format = serialization.PublicFormat.SubjectPublicKeyInfo)


def decrypt_private_key(encrypted_private_key, password, salt):
    # Derivar la clave para descifrar
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Cargar y descifrar la clave privada
    private_key = serialization.load_pem_private_key(
        encrypted_private_key,
        password=key,
        backend=default_backend()
    )
    return private_key


def deserialize_private_key(serialized_private_key):
    # Deserializar la clave privada
    private_key = serialization.load_pem_private_key(
        serialized_private_key.encode("utf-8"),
        password=None
    )
    return private_key


def deserialize_public_key(serialized_public_key):
    # Deserializar la clave pública
    public_key = serialization.load_pem_public_key(
        serialized_public_key,
        backend=default_backend()
    )
    return public_key


def encrypt_aes_message(message, aes_key):
    # Cifrar el mensaje con la clave aes
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    encrypted_message = iv + encryptor.update(message.encode()) + encryptor.finalize()
    logging.info(f"Mensaje cifrado con AES: {encrypted_message.hex()}")
    return encrypted_message


def decrypt_message(mensaje_cifrado, clave_aes):
    # Descifrar el mensaje con la clave aes
    iv = mensaje_cifrado[:16]
    ciphertext = mensaje_cifrado[16:]

    cipher = Cipher(algorithms.AES(clave_aes), modes.CFB(iv))
    decryptor = cipher.decryptor()

    mensaje_descifrado = decryptor.update(ciphertext) + decryptor.finalize()
    logging.info(f"Mensaje descifrado: {mensaje_descifrado.decode('utf-8')}")
    return mensaje_descifrado.decode("utf-8")


def generate_hmac(aes_key, encrypted_message):
    # Generar el HMAC usando la clave AES y el mensaje cifrado
    h = HMAC(aes_key, hashes.SHA256())
    h.update(encrypted_message)
    hmac_tag = h.finalize()
    logging.info(f"HMAC generado: {hmac_tag.hex()}")
    return hmac_tag


def verify_hmac(aes_key, encrypted_message, hmac_label_received):
    # Generar un nuevo HMAC usando la misma clave AES y verificar si el HMAC coincide con el recibido
    h = HMAC(aes_key, hashes.SHA256())
    h.update(encrypted_message)

    try:
        h.verify(hmac_label_received)
        logging.info("HMAC verificado correctamente. El mensaje es auténtico.")
        return True
    except InvalidSignature:
        logging.error("HMAC incorrecto. El mensaje ha sido alterado o no es auténtico.")
        return False



def encrypt_aes_rsa_key(aes_key, public_key):
    # Cifrar la clave AES usando la clave pública
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    logging.info(f"Clave AES cifrada con RSA: {encrypted_aes_key.hex()}")
    return encrypted_aes_key


def decrypt_aes_rsa_key(encrypted_aes_key, private_key):
    # Descifrar la clave AES usando la clave privada
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    logging.info(f"Clave AES descifrada con RSA: {aes_key.hex()}")
    return aes_key


def check_messages(conversations, username, private_key):
    # Verificar si los mensajes se puden descifrar con la clave privada y devolver los que si se han podido
    good_messages = []
    for message in conversations:
            if message["sender"] == username:
                try:
                    aes = decrypt_aes_rsa_key(message["aes_key_sender"], private_key)
                except:
                    return "error"
            else:
                try:
                    aes = decrypt_aes_rsa_key(message["aes_key_receiver"], private_key)
                except:
                    return "error"
            if verify_hmac(aes, message["text"], message["hmac"]):
                    message_decrypted = decrypt_message(message["text"], aes)
                    good_messages.append([message["id"], message["sender"], message_decrypted, message["datehour"]])
    return good_messages

############################################## ENTREGA 2 ######################################################
# TODO A parte de los demas todos, hay que tener en cuenta el cómo autofirmar un certificado

# TODO eliminar estas funciones
def create_petition(public_key):
    return public_key

def get_public_key(route):
    return route

                        # FUNCIONES AUXILIARES PARA LA REPRESENTACIÓN DE LOS CERTIFICADOS

# Esta función lee todos los certificados y devuelve una lista de diccionarios con los certificados y requests
def read_all_certificates_as_dict(filename):
    cert_list = []
    with open(filename, "r") as file:
        for line in file:
            entry = get_parts_as_dict(line)
            cert_list.append(entry)
    return cert_list

# Esta función recibe una línea de index y la divide en un diccionario
def get_parts_as_dict(line):
    parts = line.strip().split(", ")
    return {"index": int(parts[0]), "route": parts[1], "verification": bool(parts[2])}

# Esta función devuelve la línea de un certificado en especifico que se encuentra en index
def read_certificate_from_index(index):
    filename = "../AC/index.txt"
    with open(filename, 'r') as file:
        for line in file:
            if line.startswith(f'"{index:04d}"'):
                line.strip()
                return line
    return False


                        # FUNCIONES PARA LA CREACIÓN DE UN CERTIFICADO

#TODO renombrar a create_petition cuando esté terminado.
# Deben estar los valores "clave publica del usuario", "fecha de inicio", "fecha de expiración", "entidad superior" (default = False)
# Renombrar los valores dichos anteriormente para mayor claridad
# Aquí NO se necesita la private_key del usuario. Necesitamos la private key del AC para firmar el certificado.
def create_request(username, date, public_key, private_key):
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False
    ).add_extension(
        x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.3.6.1.4.1.343.1.1"),  # OID personalizado
            date.encode("utf-8")),
        critical=False
    )
    csr = csr_builder.sign(private_key, hashes.SHA256())
    index = get_serial() + 1
    route = f"../AC/requests/{index:04d}.pem"
    with open(route, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    update_serial(index)
    add_certificate_to_index(index, route)
    return index

# Función para obtener el número de certificados y peticiones
def get_serial():
    filename = "../AC/serial.txt"
    try:
        with open(filename, "r") as file:
            last_serial = int(file.read())
            return last_serial
    except (ValueError, FileNotFoundError):
        return f"{0:04d}"

# Función para actualizar el número de certificados y peticiones
def update_serial(index):
    filename = "../AC/serial.txt"
    with open(filename, "w") as file:
        file.write(f"{index:04d}")

# Función para añadir un certificado al index. Ejemplo: "0001, ../AC/requests/0001.pem, False"
def add_certificate_to_index(index, route, verification = False):
    filename = "../AC/index.txt"
    certificate_string = f"{index:04d}, {route}, {verification}\n"
    with open(filename, "a") as file:
        file.write(certificate_string)


                        # FUNCIONES PARA LA OBTENCIÓN DE UNA PUBLIC KEY

#TODO renombrar a get_public_key cuando esté terminado.
def get_public_key_from_certificate(index):
    route = get_parts_as_dict((read_certificate_from_index(index)))[1]
    certificate = open_certificate(route)
    if verify_cerificate(index):
        return certificate.public_key()
    return False

# Función para abrir un certificado y leer sus datos
def open_certificate(certificate):
    with open(certificate, "rb") as file:
        return x509.load_pem_x509_certificate(file.read())

# Función para verificar la firma de un certificado.
# TODO 1. Comprobar que el certificado está entre los tiempos límites (no antes y no después)
#  2. Comprobar que el certificado superior también está validado por su superior
#  3. Necesitamos el propio certificado y la public key del AC.
def verify_cerificate(index):
    try:
        # Cargar el certificado
        certificate_parameters = get_parts_as_dict((read_certificate_from_index(index)))

        # Obtener los datos firmados del certificado (TBS = "To Be Signed")
        certificate = open_certificate(certificate_parameters[1])

        # Obtener los datos To Be Signed y la firma
        tbs_cert = certificate.tbs_certificate_bytes
        signature = certificate.signature

        # Conseguimos la clave pública de AC
        ca_public_key = get_AC_public_key()

        # Verificar la firma con la clave pública de la AC
        ca_public_key.verify(
            signature,
            tbs_cert,
            padding.PKCS1v15(),  # Esquema de padding para RSA
            certificate.signature_hash_algorithm
        )

        # Si la verificación es exitosa, actualizamos el índice
        update_certificate_in_index(index, certificate_parameters[1], True)
        return True

    except Exception as e:
        print(f"Error en la verificación: {e}")
        return False

def get_AC_public_key():
    Users_table = Users()
    AC = Users_table.check_user("USUARIO AC")
    return get_public_key_from_certificate(AC)


                        # FUNCIONES PARA FIRMAR UNA PETICIÓN

# Función para firmar una petición
# TODO Recuerda actualizar el index: verification = True y cambiar la ruta del archivo (de requests a newcerts...?)
# Para firmar necesitamos únicamente la private key del AC
def sign_petition(certificate, AC_private_key):
    return

# Función para actualizar un certificado en el inex
def update_certificate_in_index(index, route, verification):
    filename = "../AC/index.txt"

    with open(filename, 'w') as file:
        for line in file:
            if line.startswith(f'"{index:04d}"'):
                #TODO está bien escrito así? Es necesario "\n"?
                new_line = f'"{index:04d}, {route}, {verification}\n"'
                file.write(new_line)
            else:
                file.write(line)

# Función para conseguir las clave privada de un usuario de AC
#TODO Recuerda que la clave privada no es así como tal
def get_AC_private_key():
    Users_table = Users()
    AC = Users_table.check_user("USUARIO AC")
    return