import os
import uuid
import sqlite3
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
from datetime import datetime, timedelta
from functools import wraps
from threading import Lock
from time import time

app = Flask(__name__)
db_file = 'app.db'
conn = sqlite3.connect(db_file, check_same_thread=False)
cur = conn.cursor()
lock = Lock()

SECRET_KEY = os.environ.get('NOT_MY_KEY', 'default_secret_key').encode()


cur.execute("""
CREATE TABLE IF NOT EXISTS private_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL
)
""")
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
""")
cur.execute("""
CREATE TABLE IF NOT EXISTS auth_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")
conn.commit()

def encrypt_data(data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return (iv + encryptor.update(data.encode()) + encryptor.finalize()).hex()

def decrypt_data(data):
    raw_data = bytes.fromhex(data)
    iv, encrypted = raw_data[:16], raw_data[16:]
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()

def rate_limited(func):
    timestamps = []

    @wraps(func)
    def wrapper(*args, **kwargs):
        now = time()
        timestamps.append(now)
        timestamps[:] = [t for t in timestamps if now - t <= 1]
        if len(timestamps) > 10:
            return jsonify({'error': 'Too many requests'}), 429
        return func(*args, **kwargs)
    return wrapper

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')

        if not username or not email:
            return jsonify({'error': 'Username and email are required'}), 400

        password = str(uuid.uuid4())
        hashed_password = sha256(password.encode()).hexdigest()

        cur.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                    (username, hashed_password, email))
        conn.commit()

        return jsonify({'message': 'User registered successfully', 'password': password}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username or email already exists'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/store-key', methods=['POST'])
def store_key():
    try:
        private_key = request.json.get('private_key')
        if not private_key:
            return jsonify({'error': 'Private key is required'}), 400

        encrypted_key = encrypt_data(private_key)
        cur.execute("INSERT INTO private_keys (key) VALUES (?)", (encrypted_key,))
        conn.commit()

        return jsonify({'message': 'Key stored successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth', methods=['POST'])
@rate_limited
def auth():
    try:
        user_id = 1
        ip = request.remote_addr

        cur.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (ip, user_id))
        conn.commit()

        token = str(uuid.uuid4())
        return jsonify({'token': token}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(port=8080)
