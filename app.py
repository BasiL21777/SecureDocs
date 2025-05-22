from app import create_app
# from flask_talisman import Talisman
import os

app = create_app()

# # Secure app with default security headers
# Talisman(app)

if __name__ == '__main__':
    cert_path = os.path.join('app', 'certs', 'cert.pem')
    key_path = os.path.join('app', 'certs', 'key.pem')
    app.run(ssl_context=(cert_path, key_path))
