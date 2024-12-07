import os
import sqlite3
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import jwt
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = 'aes_private_keys.db'
SECRET_KEY = os.environ.get('NOT_MY_KEY').encode()

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

def encrypt_key(key):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    encryption_key = kdf.derive(SECRET_KEY)
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(salt), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(key) + encryptor.finalize()
    return salt + cipher.mode.tag + encrypted_key

def decrypt_key(encrypted_key):
    salt = encrypted_key[:16]
    tag = encrypted_key[16:32]
    encrypted_data = encrypted_key[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    encryption_key = kdf.derive(SECRET_KEY)
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(salt, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

def generate_and_store_key(expiry_duration):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_key = encrypt_key(private_key_pem)
    expiry_time = int((datetime.utcnow() + expiry_duration).timestamp())
    conn = get_db_connection()
    conn.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (encrypted_key, expiry_time))
    conn.commit()
    conn.close()

def get_key(expired=False):
    conn = get_db_connection()
    if expired:
        result = conn.execute('SELECT key FROM keys WHERE exp < ?', (int(datetime.utcnow().timestamp()),)).fetchone()
    else:
        result = conn.execute('SELECT key FROM keys WHERE exp > ?', (int(datetime.utcnow().timestamp()),)).fetchone()
    conn.close()
    if result:
        return decrypt_key(result['key'])
    return None

def get_valid_keys():
    conn = get_db_connection()
    keys = conn.execute('SELECT key FROM keys WHERE exp > ?', (int(datetime.utcnow().timestamp()),)).fetchall()
    conn.close()
    public_keys = []
    for row in keys:
        private_key = serialization.load_pem_private_key(row['key'], password=None, backend=default_backend())
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_keys.append(public_key_pem)
    return public_keys

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    valid_keys = get_valid_keys()
    jwks_data = {'keys': []}
    for public_key_pem in valid_keys:
        jwks_data['keys'].append({
            'kid': '1',
            'kty': 'RSA',
            'use': 'sig',
            'alg': 'RS256',
            'n': '',
            'e': ''
        })
    return jsonify(jwks_data)

@app.route('/auth', methods=['POST'])
def auth():
    expired = 'expired' in request.args
    private_key = get_key(expired)
    if private_key is None:
        return jsonify({'error': 'No valid key found'}), 400
    payload = {'username': 'userABC', 'exp': datetime.utcnow() + timedelta(minutes=30)}
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': '1'})
    return jsonify({'token': token})

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = str(uuid.uuid4())
    password_hash = generate_password_hash(password, method='argon2')
    conn = get_db_connection()
    conn.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)', 
                 (username, password_hash, email))
    conn.commit()
    conn.close()
    return jsonify({'password': password})

if __name__ == '__main__':
    create_tables()
    generate_and_store_key(timedelta(hours=1))
    app.run(port=8080)
