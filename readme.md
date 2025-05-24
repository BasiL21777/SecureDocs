SecureDocs
SecureDocs is a Flask-based web application for securely uploading, listing, and downloading documents with AES encryption and HMAC-SHA256 integrity verification. It includes user authentication with 2FA, role-based access (Admin/User), profile image upload, and plans for Okta integration.
Prerequisites

Python 3.8 or higher
MySQL 8.0 or higher
OpenSSL (for SSL certificates)
Git (optional, for cloning the repository)
Windows, Linux, or macOS

Setup Instructions
Follow these steps to set up and run the SecureDocs application locally.
1. Clone the Repository (Optional)
If you have the project in a Git repository, clone it:
git clone <repository-url>
cd SecureDocs

Otherwise, navigate to the project directory:
cd D:\Learn Flask\Final_DI\SecureDocs

2. Create and Activate a Virtual Environment
Create a virtual environment to isolate dependencies:
python -m venv venv

Activate the virtual environment:

Windows:
.\venv\Scripts\activate


Linux/macOS:
source venv/bin/activate



3. Install Dependencies
Install the required Python packages:
pip install flask flask-sqlalchemy flask-login flask-migrate authlib pyotp qrcode pillow mysql-connector-python pycryptodome bcrypt python-dotenv

The key dependencies include:
Flask==2.0.1
Flask-SQLAlchemy==3.0.5
Flask-Login==0.6.3
Flask-Migrate==4.0.7
authlib==1.3.2
pyotp==2.9.0
qrcode==7.4.2
Pillow==10.4.0
mysql-connector-python==9.0.0
pycryptodome==3.20.0
bcrypt==4.2.0
python-dotenv==1.0.1

Save these to requirements.txt:
pip freeze > requirements.txt

4. Generate Cryptographic Keys
The application uses AES for encryption and HMAC-SHA256 for integrity. Generate keys using test.py.
Create test.py in the project root (D:\Learn Flask\Final_DI\SecureDocs):
import os
import base64

# Generate a 32-byte AES key
aes_key = base64.b64encode(os.urandom(32)).decode()
# Generate a 16-byte HMAC key
hmac_key = base64.b64encode(os.urandom(16)).decode()

print("AES_KEY:", aes_key)
print("HMAC_KEY:", hmac_key)

Run the script:
python test.py

Copy the output (AES_KEY and HMAC_KEY).
5. Configure the .env File
Create or update .env in the project root with the following, replacing placeholders:
SECRET_KEY=your-secret-key
MYSQL_USER=secure_user
MYSQL_PASSWORD=your-mysql-password
SQLALCHEMY_DATABASE_URI=mysql+mysqlconnector://secure_user:your-mysql-password@localhost/secure_docs
SQLALCHEMY_TRACK_MODIFICATIONS=False
AES_KEY=<paste-aes-key-from-test.py>
HMAC_KEY=<paste-hmac-key-from-test.py>


SECRET_KEY: Random string (e.g., os.urandom(24).hex()).
MYSQL_USER/MYSQL_PASSWORD: MySQL credentials.
AES_KEY/HMAC_KEY: From test.py.

Example .env:
SECRET_KEY=your-random-secret-key-1234567890
MYSQL_USER=secure_user
MYSQL_PASSWORD=secure_password
SQLALCHEMY_DATABASE_URI=mysql+mysqlconnector://secure_user:secure_password@localhost/secure_docs
SQLALCHEMY_TRACK_MODIFICATIONS=False
AES_KEY=your-32-byte-aes-key-in-base64
HMAC_KEY=your-16-byte-hmac-key-in-base64

6. Set Up MySQL Database
Install MySQL if not already installed, then create the database:
mysql -u root -p

In the MySQL shell:
CREATE DATABASE secure_docs;
CREATE USER 'secure_user'@'localhost' IDENTIFIED BY 'your-mysql-password';
GRANT ALL PRIVILEGES ON secure_docs.* TO 'secure_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;

The Flask app will create tables automatically via db.create_all() in app/__init__.py.
7. Create Upload Directories
Create directories for document and profile image uploads:
mkdir D:\Learn Flask\Final_DI\SecureDocs\app\static\uploads
mkdir D:\Learn Flask\Final_DI\SecureDocs\app\static\images\profiles

8. Run the Application
Start the Flask server with SSL:
python app.py

Access the app at https://127.0.0.1:5000 (ignore self-signed certificate warning).
9. Test the Application

Register: Go to /auth/register to create a user.
Login: Log in at /auth/login and complete 2FA setup.
Profile:
Visit /user/profile to update username, email, password, or upload a profile image (JPG/PNG/GIF, <2MB).
Verify image displays with a WhatsApp-style green gradient border.


Upload Document:
Upload a PDF/DOCX/TXT at /documents/documents.
Verify file appears in the document list.


Admin Features:
Set a user as admin:UPDATE users SET role='Admin' WHERE username='test_user';


Log in, go to /admin/dashboard to view stats (users, documents, storage).
Check /admin/logs and download logs as CSV via "Download All Logs as CSV".


Verify Storage:
Ensure non-zero storage on /admin/dashboard:SELECT id, name, size FROM documents;
SELECT SUM(size) AS total_size FROM documents;





Project Structure
SecureDocs/
├── app/
│   ├── auth/
│   │   ├── routes.py
│   │   └── templates/
│   ├── documents/
│   │   ├── routes.py
│   │   └── templates/
│   ├── models/
│   │   ├── user.py
│   │   ├── document.py
│   │   └── audit_log.py
│   ├── user/
│   │   ├── routes.py
│   │   └── templates/
│   ├── admin/
│   │   ├── routes.py
│   │   └── templates/
│   ├── static/
│   │   ├── uploads/           # Encrypted documents
│   │   ├── images/
│   │   │   ├── profiles/     # Profile images
│   │   ├── css/
│   │   └── js/
│   ├── templates/             # Base and shared templates
│   ├── certs/                # SSL certificates
│   └── __init__.py
├── venv/                     # Virtual environment
├── .env                      # Environment variables
├── app.py                    # Entry point
├── requirements.txt          # Dependencies
└── test.py                   # Key generation script

Notes

Encryption: Documents are encrypted with AES and verified with HMAC-SHA256.
2FA: Enabled via TOTP (QR code setup at login).
Profile Images: Stored in app/static/images/profiles/, displayed with a green gradient border.
Admin Features: Include user/document management, system logs, and CSV export.
Okta Integration: Planned but not yet implemented.
Logs: Check app.log for debugging:type D:\Learn Flask\Final_DI\SecureDocs\app.log



