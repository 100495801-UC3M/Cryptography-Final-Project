# config.py

class Config:
    # Configuración básica de Flask-Mail
    MAIL_SERVER = 'smtp.gmail.com'      # Servidor SMTP de tu proveedor de correo
    MAIL_PORT = 587                       # Puerto (587 para TLS, 465 para SSL)
    MAIL_USE_TLS = True                   # Activa TLS
    MAIL_USE_SSL = False                  # Cambia a True si usas SSL en vez de TLS
    MAIL_USERNAME = '100495801@alumnos.uc3m.es' # Dirección de correo electrónico
    MAIL_PASSWORD = 'Alola_265_265'        # Contraseña de correo electrónico
    MAIL_DEFAULT_SENDER = '100495801@alumnos.uc3m.es' # Dirección predeterminada del remitente

    # Configuraciones adicionales
    MAIL_MAX_EMAILS = None                # Número máximo de correos a enviar (None para sin límite)
    MAIL_ASCII_ATTACHMENTS = False        # Adjuntos en ASCII
