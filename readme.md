# SecureDocs

SecureDocs is a Flask-based web application for securely uploading, listing, and downloading documents with AES encryption and HMAC-SHA256 integrity verification. It includes user authentication, role-based access, and plans for Okta integration.

## Prerequisites

- Python 3.8 or higher
- OpenSSL (for SSL certificates)
- Git (optional, for cloning the repository)
- Windows, Linux, or macOS

## Setup Instructions

Follow these steps to set up and run the SecureDocs application locally.

### 1. Clone the Repository (Optional)

If you have the project in a Git repository, clone it:

```bash
git clone <repository-url>
cd Data_Intgrity_Final
```

Otherwise, navigate to the project directory:

```bash
cd D:\Learn Flask\Data_Intgrity_Final
```

### 2. Create and Activate a Virtual Environment

Create a virtual environment to isolate dependencies:

```bash
python -m venv venv
```

Activate the virtual environment:

- **Windows**:

    ```bash
    .\venv\Scripts\activate
    ```

- **Linux/macOS**:

    ```bash
    source venv/bin/activate
    ```


### 3. Install Dependencies

Install the required Python packages listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

The `requirements.txt` includes:

```
Flask==2.0.1
Flask-SQLAlchemy==3.0.5
python-dotenv==1.0.1
bcrypt==4.2.0
pycryptodome==3.20.0
Flask-Login==0.6.3
```

### 4. Generate Cryptographic Keys

The application uses AES for encryption and HMAC-SHA256 for integrity. Generate the keys using the provided `test.py` script.

Create a file named `test.py` in the project root (`D:\Learn Flask\Data_Intgrity_Final`):

```python
import os
import base64

# Generate a 32-byte AES key
aes_key = base64.b64encode(os.urandom(32)).decode()
# Generate a 16-byte HMAC key
hmac_key = base64.b64encode(os.urandom(16)).decode()

print("AES_KEY:", aes_key)
print("HMAC_KEY:", hmac_key)
```

Run the script to generate the keys:

```bash
python test.py
```

Copy the output (e.g., `AES_KEY: <base64-string>` and `HMAC_KEY: <base64-string>`).

### 5. Configure the .env File

Create or update the `.env` file in the project root with the following content, replacing placeholders with your keys:

```bash
SECRET_KEY=your-secret-key
SQLALCHEMY_DATABASE_URI=sqlite:///secure_docs.db
SQLALCHEMY_TRACK_MODIFICATIONS=False
AES_KEY=<paste-aes-key-from-test.py>
HMAC_KEY=<paste-hmac-key-from-test.py>
```

- **SECRET_KEY**: A random string for Flask session security (e.g., generate with `os.urandom(24).hex()`).
- **AES_KEY**: The 32-byte base64-encoded key from `test.py`.
- **HMAC_KEY**: The 16-byte base64-encoded key from `test.py`.

Example `.env`:

```bash
SECRET_KEY=your-random-secret-key-1234567890
SQLALCHEMY_DATABASE_URI=sqlite:///secure_docs.db
SQLALCHEMY_TRACK_MODIFICATIONS=False
AES_KEY=your-32-byte-aes-key-in-base64
HMAC_KEY=your-16-byte-hmac-key-in-base64
```

### 8. Run the Application

Start the Flask development server with SSL:

```bash
python app.py
```

The app will be available at `https://localhost:5000`. Open this URL in your browser (ignore the self-signed certificate warning).

### 9. Test the Application

1. **Register**: Visit `https://localhost:5000/auth/register` to create a user.
2. **Login**: Log in at `https://localhost:5000/auth/login`.
3. **Upload**: Upload a PDF, DOCX, or TXT file at `https://localhost:5000/documents/upload`.
4. **List**: View your documents at `https://localhost:5000/documents/list`.
5. **Download**: Download a document by clicking the "Download" link in the list.

## Project Structure

```
Data_Intgrity_Final/
├── app/
│   ├── auth/
│   ├── documents/
│   ├── models/
│   ├── user/
│   ├── admin/
│   ├── uploads/           # Encrypted files
│   ├── certs/            # SSL certificates
│   ├── templates/        # HTML templates
│   ├── __init__.py
│   └── static/           # CSS, JS (if any)
├── venv/                 # Virtual environment
├── secure_docs.db        # SQLite database
├── .env                  # Environment variables
├── app.py                # Entry point
├── requirements.txt      # Dependencies
└── test.py               # Key generation script
```
