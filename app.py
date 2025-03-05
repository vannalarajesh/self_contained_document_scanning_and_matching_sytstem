from flask import Flask, request, jsonify, session
import os
import sqlite3
import secrets
import datetime
import PyPDF2
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from datetime import datetime




app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
CORS(app, supports_credentials=True, origins=["http://127.0.0.1:5500", "http://localhost:5500", "null"])

MAX_SCANS_PER_DAY = 20
MAX_FILE_SIZE = 5 * 1024 * 1024  


def init_db():
    conn = sqlite3.connect('pdf_scanner.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT,
        matched_words INTEGER NOT NULL,
        credit_score INTEGER NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.commit()
    conn.close()

init_db()

def get_db_connection():
    """Create a database connection"""
    conn = sqlite3.connect('pdf_scanner.db')
    conn.row_factory = sqlite3.Row  
    return conn

def extract_text_from_pdf(pdf_file):
    """Extract text content from a PDF file"""
    try:
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        text = " ".join([page.extract_text() or "" for page in pdf_reader.pages])
        return text.lower()
    except Exception as e:
        print(f"Error extracting text from PDF: {e}")
        return ""

def get_user_by_email(email):
    """Get user data by email"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return user

def require_auth(func):
    """Decorator to require authentication for routes"""
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"message": "Authentication required"}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def get_today_scan_count(user_id):
    """Check how many scans a user has done today"""
    conn = get_db_connection()
    today = datetime.today().strftime('%Y-%m-%d')

    scan_count = conn.execute('''
        SELECT COUNT(*) FROM scans 
        WHERE user_id = ? AND DATE(timestamp) = ?
    ''', (user_id, today)).fetchone()[0]

    conn.close()
    return scan_count

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'  
    response.headers['X-XSS-Protection'] = '1; mode=block'  
    response.headers['Content-Security-Policy'] = "default-src 'self'"  
    return response

@app.route('/', methods=['GET'])
def index():
    return jsonify({"message": "PDF Scanner API is running"}), 200

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        if not all(key in data for key in ['name', 'email', 'password']):
            return jsonify({"message": "Missing required fields"}), 400
        
        name, email, password = data['name'], data['email'], data['password']
        
        if '@' not in email or '.' not in email:
            return jsonify({"message": "Invalid email format"}), 400
        if len(password) < 6:
            return jsonify({"message": "Password must be at least 6 characters"}), 400
        if get_user_by_email(email):
            return jsonify({"message": "Email already registered"}), 409
        
        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        conn.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, hashed_password))
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Registration successful"}), 201
        
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({"message": "Server error during registration"}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        if not all(key in data for key in ['email', 'password']):
            return jsonify({"message": "Email and password required"}), 400
        
        email, password = data['email'], data['password']
        user = get_user_by_email(email)
        
        if user and check_password_hash(user['password'], password):
            session.clear()  
            session['user_id'] = user['id']
            session['email'] = user['email']
            session.modified = True  
            return jsonify({"message": "Login successful", "name": user['name']}), 200
        
        return jsonify({"message": "Invalid email or password"}), 401
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"message": "Server error during login"}), 500

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200


@app.route('/scan-pdf', methods=['POST'])
@require_auth
def scan_pdf():
    try:

        user_id = session['user_id']
        scan_count_today = get_today_scan_count(user_id)

        if scan_count_today >= MAX_SCANS_PER_DAY:
            return jsonify({"message": "Daily scan limit reached (20 per day). Try again tomorrow."}), 403

        if 'pdf' not in request.files:
            return jsonify({"message": "No PDF file uploaded"}), 400

        pdf_file = request.files['pdf']
        if request.content_length > MAX_FILE_SIZE:
            return jsonify({"message": "File size exceeds 5MB limit"}), 400
        if not pdf_file.filename.lower().endswith('.pdf'):
            return jsonify({"message": "Uploaded file is not a valid PDF"}), 400

        keywords_str = request.form.get('keywords', '')
        keywords = [kw.strip().lower() for kw in keywords_str.split(',') if kw.strip()]
        filename = request.form.get('filename', 'unnamed.pdf')

        if not keywords:
            return jsonify({"message": "No keywords provided"}), 400

        extracted_text = extract_text_from_pdf(pdf_file)
        if not extracted_text:
            return jsonify({"message": "Could not extract text from PDF"}), 400

        match_count = sum(1 for keyword in keywords if keyword in extracted_text)
        credit_score = int((match_count / len(keywords)) * 100) if keywords else 0

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO scans (user_id, filename, matched_words, credit_score) VALUES (?, ?, ?, ?)',
            (user_id, filename, match_count, credit_score)
        )
        conn.commit()
        conn.close()

        return jsonify({
            "message": "Document scanned successfully",
            "matched_words": match_count,
            "credit_score": credit_score,
            "scans_remaining": MAX_SCANS_PER_DAY - scan_count_today - 1  # Show remaining scans
        })
    except Exception as e:
        print(f"Error scanning PDF: {e}")
        return jsonify({"message": "Error processing PDF"}), 500

@app.route('/user/scans', methods=['GET'])
@require_auth
def get_user_scans():
    try:
        conn = get_db_connection()
        scans = conn.execute('SELECT filename, matched_words, credit_score, timestamp FROM scans WHERE user_id = ? ORDER BY timestamp DESC', (session['user_id'],)).fetchall()
        conn.close()
        
        return jsonify({"scans": [dict(scan) for scan in scans]})
    except Exception as e:
        print(f"Error retrieving scans: {e}")
        return jsonify({"message": "Error retrieving scan history"}), 500

if __name__ == '__main__':
    app.run(debug=True)
