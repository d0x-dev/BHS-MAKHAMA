import os
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import json
from datetime import datetime, timedelta
import sqlite3
from functools import wraps
import secrets

# Google Drive API imports
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
import google.auth.transport.requests

app = Flask(__name__)
app.config.from_pyfile('config.py')
app.secret_key = app.config['SECRET_KEY']

# Enable insecure transport for local development (remove in production)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Google Drive API configuration
CLIENT_SECRETS_FILE = 'credentials.json'
SCOPES = ['https://www.googleapis.com/auth/drive.file']
API_SERVICE_NAME = 'drive'
API_VERSION = 'v3'

# Session configuration - keeps users logged in until they logout
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=30)  # Sessions last 30 days
)

# Login attempt limits
MAX_LOGIN_ATTEMPTS = 4
BLOCK_TIME_HOURS = 24
FAILED_ATTEMPTS_FILE = 'failed_attempts.json'

# File paths for user data
USERS_FILE = 'users.json'
PENDING_FILE = 'pending_users.json'
DECLINED_FILE = 'declined_users.json'

def load_json(file_path):
    try:
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                json.dump([], f)
            return []
        
        with open(file_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

def save_json(data, file_path):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)

# Database setup
def get_db_connection():
    conn = sqlite3.connect('school.db')
    conn.row_factory = sqlite3.Row
    return conn

from werkzeug.security import generate_password_hash
from datetime import datetime

def init_db():
    with app.app_context():
        try:
            conn = get_db_connection()
            c = conn.cursor()

            # Create tables
            c.execute('''
                CREATE TABLE IF NOT EXISTS admin (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    last_login TEXT
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    date_posted TEXT NOT NULL,
                    is_pinned INTEGER DEFAULT 0
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    upload_date TEXT NOT NULL,
                    drive_file_id TEXT
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS syllabus (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    class_name TEXT NOT NULL,
                    year TEXT NOT NULL,
                    month TEXT NOT NULL,
                    exam_name TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    upload_date TEXT NOT NULL,
                    drive_file_id TEXT
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    message TEXT NOT NULL,
                    date TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    admin_notes TEXT
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS classwork (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    class_name TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    filename TEXT NOT NULL,
                    upload_date TEXT NOT NULL,
                    due_date TEXT,
                    drive_file_id TEXT
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS homework (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    class_name TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    filename TEXT NOT NULL,
                    upload_date TEXT NOT NULL,
                    due_date TEXT,
                    drive_file_id TEXT
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS books (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    author TEXT,
                    subject TEXT,
                    class_name TEXT,
                    filename TEXT NOT NULL,
                    upload_date TEXT NOT NULL,
                    drive_file_id TEXT
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    session_token TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    login_time TEXT NOT NULL,
                    user_agent TEXT,
                    FOREIGN KEY (username) REFERENCES admin(username)
                )
            ''')

            # Insert default admin if not exists
            existing_admin = c.execute('SELECT * FROM admin WHERE username = ?', ('admin',)).fetchone()
            if not existing_admin:
                c.execute(
                    'INSERT INTO admin (username, password, last_login) VALUES (?, ?, ?)',
                    ('admin', generate_password_hash('admin123'), datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                )

            conn.commit()
        except Exception as e:
            print("Database initialization failed:", e)
        finally:
            conn.close()

init_db()

def allowed_file(filename, allowed_extensions=None):
    if allowed_extensions is None:
        allowed_extensions = app.config['ALLOWED_EXTENSIONS']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

# Google Drive functions
def get_drive_service():
    if 'credentials' not in session:
        return None
    
    credentials = Credentials(
        token=session['credentials']['token'],
        refresh_token=session['credentials']['refresh_token'],
        token_uri=session['credentials']['token_uri'],
        client_id=session['credentials']['client_id'],
        client_secret=session['credentials']['client_secret'],
        scopes=session['credentials']['scopes']
    )
    
    if credentials.expired:
        credentials.refresh(Request())
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
    
    return build(API_SERVICE_NAME, API_VERSION, credentials=credentials)

def upload_to_drive(file_path, file_name, folder_id=None):
    try:
        drive_service = get_drive_service()
        if not drive_service:
            return None
            
        file_metadata = {
            'name': file_name,
            'mimeType': 'application/octet-stream'
        }
        
        if folder_id:
            file_metadata['parents'] = [folder_id]
        
        media = MediaFileUpload(file_path, resumable=True)
        file = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, webViewLink'
        ).execute()
        
        return file
    except Exception as e:
        print(f"Error uploading to Google Drive: {e}")
        return None

def delete_from_drive(file_id):
    try:
        drive_service = get_drive_service()
        if drive_service and file_id:
            drive_service.files().delete(fileId=file_id).execute()
            return True
        return False
    except Exception as e:
        print(f"Error deleting file from Google Drive: {e}")
        return False

# Auth decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login', next=request.url))
        
        # Verify the session is still valid
        conn = get_db_connection()
        try:
            active_session = conn.execute(
                'SELECT * FROM user_sessions WHERE username = ? AND session_token = ?',
                (session['username'], session.get('session_token', ''))
            ).fetchone()
            
            if not active_session:
                session.clear()
                flash('Your session is no longer valid', 'warning')
                return redirect(url_for('login'))
        finally:
            conn.close()
            
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Please log in as admin to access this page', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Session management functions
def record_user_session(username, session_token, ip_address):
    conn = get_db_connection()
    try:
        # End any existing sessions for this user
        conn.execute('DELETE FROM user_sessions WHERE username = ?', (username,))
        
        # Record new session
        conn.execute(
            '''INSERT INTO user_sessions 
            (username, session_token, ip_address, login_time, user_agent) 
            VALUES (?, ?, ?, ?, ?)''',
            (username, session_token, ip_address, datetime.now().isoformat(), request.user_agent.string)
        )
        conn.commit()
    finally:
        conn.close()

def validate_user_session(username, session_token):
    conn = get_db_connection()
    try:
        session_data = conn.execute(
            'SELECT * FROM user_sessions WHERE username = ? AND session_token = ?',
            (username, session_token)
        ).fetchone()
        return session_data is not None
    finally:
        conn.close()

# Login attempt functions
def load_failed_attempts():
    try:
        with open(FAILED_ATTEMPTS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_failed_attempts(data):
    with open(FAILED_ATTEMPTS_FILE, 'w') as f:
        json.dump(data, f)

def is_blocked(username, ip_address):
    attempts_data = load_failed_attempts()
    now = datetime.now()
    
    # Check by username
    if username in attempts_data:
        last_attempt = datetime.fromisoformat(attempts_data[username]['timestamp'])
        if attempts_data[username]['attempts'] >= MAX_LOGIN_ATTEMPTS:
            if now - last_attempt < timedelta(hours=BLOCK_TIME_HOURS):
                return True
            else:
                # Block period expired, reset attempts
                attempts_data[username]['attempts'] = 0
                save_failed_attempts(attempts_data)
    
    # Check by IP address
    if ip_address in attempts_data:
        last_attempt = datetime.fromisoformat(attempts_data[ip_address]['timestamp'])
        if attempts_data[ip_address]['attempts'] >= MAX_LOGIN_ATTEMPTS:
            if now - last_attempt < timedelta(hours=BLOCK_TIME_HOURS):
                return True
            else:
                # Block period expired, reset attempts
                attempts_data[ip_address]['attempts'] = 0
                save_failed_attempts(attempts_data)
    
    return False

def record_failed_attempt(username, ip_address):
    attempts_data = load_failed_attempts()
    now = datetime.now().isoformat()
    
    # Track by username
    if username in attempts_data:
        attempts_data[username]['attempts'] += 1
        attempts_data[username]['timestamp'] = now
    else:
        attempts_data[username] = {'attempts': 1, 'timestamp': now}
    
    # Track by IP address
    if ip_address in attempts_data:
        attempts_data[ip_address]['attempts'] += 1
        attempts_data[ip_address]['timestamp'] = now
    else:
        attempts_data[ip_address] = {'attempts': 1, 'timestamp': now}
    
    save_failed_attempts(attempts_data)

# Google Drive authorization routes
@app.route('/authorize')
def authorize():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    # Store the state in the session so the callback can verify the auth server response
    session['state'] = state

    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    # Specify the state when creating the flow in the callback so that it can
    # verify the authorization server response
    state = session['state']

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for('oauth2callback', _external=True)
    )

    # Use the authorization server's response to fetch the OAuth 2.0 tokens
    flow.fetch_token(authorization_response=request.url)

    # Store the credentials in the session
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    return redirect(url_for('admin_dashboard'))

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        # Check if session is still valid
        if validate_user_session(session['username'], session.get('session_token', '')):
            return redirect(url_for('home'))
        else:
            session.clear()
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr

        # First check if it's an admin login
        conn = get_db_connection()
        admin = conn.execute('SELECT * FROM admin WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if admin and check_password_hash(admin['password'], password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        
        # If not admin, proceed with regular user login
        if is_blocked(username, ip_address):
            flash('Too many failed attempts. Please try again after 24 hours.', 'danger')
            return redirect(url_for('login'))

        declined_users = load_json('declined_users.json')
        declined_user = next((u for u in declined_users if u['username'] == username), None)
        if declined_user:
            reason = declined_user.get('reason', 'No reason provided')
            flash(f'You are Declined. Reason: {reason}', 'danger')
            return redirect(url_for('login'))

        users = load_json(USERS_FILE)
        user = next((u for u in users if u['username'] == username), None)

        if user and user['password'] == password:
            attempts_data = load_failed_attempts()
            if username in attempts_data:
                attempts_data[username]['attempts'] = 0
            if ip_address in attempts_data:
                attempts_data[ip_address]['attempts'] = 0
            save_failed_attempts(attempts_data)

            # Create new session
            session_token = secrets.token_hex(16)
            session['logged_in'] = True
            session['username'] = username
            session['role'] = user.get('role', 'student')
            session['session_token'] = session_token
            session['ip_address'] = ip_address
            
            # Record session in database
            record_user_session(username, session_token, ip_address)
            
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            record_failed_attempt(username, ip_address)
            flash('Invalid username or password', 'danger')

    return render_template('login.html')
    
@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        if not all([name, email, subject, message]):
            flash('Please fill all required fields', 'danger')
            return redirect(url_for('contact'))
        
        try:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO feedback (name, email, subject, message, date) VALUES (?, ?, ?, ?, ?)',
                (name, email, subject, message, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            conn.commit()
            conn.close()
            
            flash('Your message has been sent successfully!', 'success')
            return redirect(url_for('contact'))
        except Exception as e:
            print(f"Error processing contact form: {e}")
            flash('An error occurred while sending your message', 'danger')
    return render_template('contact.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        # Remove session from database
        conn = get_db_connection()
        try:
            conn.execute(
                'DELETE FROM user_sessions WHERE username = ? AND session_token = ?',
                (session['username'], session.get('session_token', ''))
            )
            conn.commit()
        finally:
            conn.close()
    
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            username = request.form.get('username')
            password = request.form.get('password')
            class_name = request.form.get('class')
            roll_number = request.form.get('roll_number')
            
            if not all([first_name, last_name, username, password, class_name, roll_number]):
                flash('Please fill all required fields', 'danger')
                return redirect(url_for('signup'))
            
            # Check if username exists
            all_users = load_json(USERS_FILE) + load_json(PENDING_FILE) + load_json(DECLINED_FILE)
            if any(u['username'] == username for u in all_users):
                flash('Username already exists', 'danger')
                return redirect(url_for('signup'))
            
            new_user = {
                'first_name': first_name,
                'last_name': last_name,
                'username': username,
                'password': password,
                'class': class_name,
                'roll_number': roll_number,
                'status': 'pending',
                'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Save to pending users
            pending_users = load_json(PENDING_FILE)
            pending_users.append(new_user)
            save_json(pending_users, PENDING_FILE)
            
            flash('Your application has been submitted for admin approval', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error during signup: {e}")
            flash('An error occurred during registration', 'danger')
    
    return render_template('signup.html')

@app.route('/home')
@login_required
def home():
    conn = get_db_connection()
    try:
        pinned_notices = conn.execute('SELECT * FROM notifications WHERE is_pinned = 1 ORDER BY date_posted DESC LIMIT 2').fetchall()
        recent_syllabus = conn.execute('SELECT * FROM syllabus ORDER BY upload_date DESC LIMIT 2').fetchall()
        return render_template('index.html', pinned_notices=pinned_notices, recent_syllabus=recent_syllabus)
    finally:
        conn.close()

@app.route('/documents')
@login_required
def documents():
    conn = get_db_connection()
    try:
        documents = conn.execute('SELECT * FROM documents ORDER BY upload_date DESC').fetchall()
        return render_template('documents.html', documents=documents)
    finally:
        conn.close()

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                             'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/syllabus')
@login_required
def syllabus():
    conn = get_db_connection()
    try:
        syllabus = conn.execute('''
            SELECT * FROM syllabus 
            ORDER BY year DESC, class_name ASC, subject ASC
        ''').fetchall()
        return render_template('syllabus.html', syllabus=syllabus)
    finally:
        conn.close()

@app.route('/account')
@login_required
def account():
    return render_template('account.html', username=session.get('username'))

@app.route('/notifications')
@login_required
def notifications():
    conn = get_db_connection()
    try:
        notifications = conn.execute('SELECT * FROM notifications ORDER BY date_posted DESC').fetchall()
        return render_template('notifications.html', notifications=notifications)
    finally:
        conn.close()

from flask import send_file
import io

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    local_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Step 1: Serve from local disk if it exists
    if os.path.exists(local_path):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    
    # Step 2: Check database for Google Drive file ID
    conn = get_db_connection()
    file_id = None
    for table in ['documents', 'syllabus', 'classwork', 'homework', 'books']:
        result = conn.execute(f'SELECT drive_file_id FROM {table} WHERE filename = ?', (filename,)).fetchone()
        if result and result['drive_file_id']:
            file_id = result['drive_file_id']
            break

    # Step 3: If found on Drive, download and serve
    if file_id:
        try:
            drive_service = get_drive_service()
            if drive_service:
                request = drive_service.files().get_media(fileId=file_id)
                fh = io.BytesIO()
                downloader = MediaIoBaseDownload(fh, request)
                done = False
                while not done:
                    status, done = downloader.next_chunk()
                fh.seek(0)
                return send_file(fh, as_attachment=True, download_name=filename)
        except Exception as e:
            print(f"[ERROR] Failed to download from Drive: {e}")
    
    flash('File not found.', 'danger')
    return redirect(url_for('home'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        # Verify the admin session is still valid
        conn = get_db_connection()
        try:
            admin = conn.execute('SELECT * FROM admin WHERE username = ?', 
                               (session['admin_username'],)).fetchone()
            if admin:
                return redirect(url_for('admin_dashboard'))
        finally:
            conn.close()
            
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr
        
        # Check if admin/IP is blocked
        if is_blocked(username, ip_address):
            flash('Too many failed attempts. Please try again after 24 hours.', 'danger')
            return redirect(url_for('admin_login'))
        
        conn = get_db_connection()
        try:
            admin = conn.execute('SELECT * FROM admin WHERE username = ?', (username,)).fetchone()
            
            if admin and check_password_hash(admin['password'], password):
                # Successful login - reset attempts if any
                attempts_data = load_failed_attempts()
                if username in attempts_data:
                    attempts_data[username]['attempts'] = 0
                    save_failed_attempts(attempts_data)
                if ip_address in attempts_data:
                    attempts_data[ip_address]['attempts'] = 0
                    save_failed_attempts(attempts_data)
                
                # Set session variables
                session['admin_logged_in'] = True
                session['admin_username'] = username
                session.permanent = True
                
                # Update last login time
                conn.execute(
                    'UPDATE admin SET last_login = ? WHERE username = ?',
                    (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username)
                )
                conn.commit()
                
                flash('Login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                # Failed login - record attempt
                record_failed_attempt(username, ip_address)
                flash('Invalid username or password', 'danger')
        finally:
            conn.close()
            
    return render_template('admin/login.html')

@app.route('/profile')
@login_required
def profile():
    # Get user data from users.json
    users = load_json(USERS_FILE)
    user = next((u for u in users if u['username'] == session['username']), None)
    
    if not user:
        flash('User profile not found', 'danger')
        return redirect(url_for('home'))
    
    return render_template('profile.html', user=user)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    users = load_json(USERS_FILE)
    user = next((u for u in users if u['username'] == session['username']), None)
    
    if not user:
        flash('User profile not found', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            # Update user data
            user['first_name'] = request.form.get('first_name', user['first_name'])
            user['last_name'] = request.form.get('last_name', user['last_name'])
            user['class'] = request.form.get('class', user['class'])
            user['roll_number'] = request.form.get('roll_number', user['roll_number'])
            
            # Save updated data
            updated_users = [u if u['username'] != session['username'] else user for u in users]
            save_json(updated_users, USERS_FILE)
            
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            print(f"Error updating profile: {e}")
            flash('Failed to update profile', 'danger')
    
    return render_template('edit_profile.html', user=user)

@app.route('/about-app')
@login_required
def about_app():
    return render_template('about_app.html')

@app.route('/developer')
@login_required
def developer():
    developers = [
        {
            'name': 'Dar Furkan',
            'email': 'Fdar336@outlook.com',
            'phone': '+919682303969',
            'github': 'https://github.com'
        },
        {
            'name': 'Ubaid Bilal',
            'email': 'Ubaid@gmail.com',
            'phone': '+917006336467',
            'github': 'https://github.com'
        }
    ]
    return render_template('developer.html', developers=developers)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    try:
        # Get counts for dashboard
        notifications_count = conn.execute('SELECT COUNT(*) FROM notifications').fetchone()[0]
        syllabus_count = conn.execute('SELECT COUNT(*) FROM syllabus').fetchone()[0]
        documents_count = conn.execute('SELECT COUNT(*) FROM documents').fetchone()[0]
        feedbacks_count = conn.execute('SELECT COUNT(*) FROM feedback').fetchone()[0]
        
        # Get recent feedbacks
        feedbacks = conn.execute('SELECT * FROM feedback ORDER BY date DESC LIMIT 5').fetchall()
        
        # Load user approval stats
        pending_users = load_json(PENDING_FILE)
        approved_users = load_json(USERS_FILE)
        declined_users = load_json(DECLINED_FILE)

        pending_approvals = len(pending_users)
        approved_count = len(approved_users)
        declined_count = len(declined_users)
        
        return render_template('admin/dashboard.html',
                               notifications_count=notifications_count,
                               syllabus_count=syllabus_count,
                               documents_count=documents_count,
                               feedbacks_count=feedbacks_count,
                               feedbacks=feedbacks,
                               pending_approvals=pending_approvals,
                               approved_users=approved_count,
                               declined_users=declined_count,
                               hide_header=True)
    finally:
        conn.close()

@app.route('/classwork', methods=['GET', 'POST'])
@login_required
def classwork():
    conn = get_db_connection()
    try:
        if request.method == 'POST':
            class_name = request.form.get('class_name')
            subject = request.form.get('subject')
            
            query = 'SELECT * FROM classwork WHERE 1=1'
            params = []
            
            if class_name and class_name != 'all':
                query += ' AND class_name = ?'
                params.append(class_name)
            
            if subject and subject != 'all':
                query += ' AND subject = ?'
                params.append(subject)
            
            query += ' ORDER BY upload_date DESC'
            classwork = conn.execute(query, params).fetchall()
            
            # Get distinct classes and subjects for dropdowns
            classes = conn.execute('SELECT DISTINCT class_name FROM classwork ORDER BY class_name').fetchall()
            subjects = conn.execute('SELECT DISTINCT subject FROM classwork ORDER BY subject').fetchall()
            
            return render_template('classwork.html', 
                                classwork=classwork,
                                classes=classes,
                                subjects=subjects,
                                selected_class=class_name,
                                selected_subject=subject)
        
        # Default GET request
        classwork = conn.execute('SELECT * FROM classwork ORDER BY upload_date DESC LIMIT 10').fetchall()
        classes = conn.execute('SELECT DISTINCT class_name FROM classwork ORDER BY class_name').fetchall()
        subjects = conn.execute('SELECT DISTINCT subject FROM classwork ORDER BY subject').fetchall()
        
        return render_template('classwork.html',
                            classwork=classwork,
                            classes=classes,
                            subjects=subjects,
                            selected_class='all',
                            selected_subject='all')
    finally:
        conn.close()

@app.route('/homework', methods=['GET', 'POST'])
@login_required
def homework():
    conn = get_db_connection()
    try:
        if request.method == 'POST':
            class_name = request.form.get('class_name')
            subject = request.form.get('subject')
            
            query = 'SELECT * FROM homework WHERE 1=1'
            params = []
            
            if class_name and class_name != 'all':
                query += ' AND class_name = ?'
                params.append(class_name)
            
            if subject and subject != 'all':
                query += ' AND subject = ?'
                params.append(subject)
            
            query += ' ORDER BY upload_date DESC'
            homework = conn.execute(query, params).fetchall()
            
            classes = conn.execute('SELECT DISTINCT class_name FROM homework ORDER BY class_name').fetchall()
            subjects = conn.execute('SELECT DISTINCT subject FROM homework ORDER BY subject').fetchall()
            
            return render_template('homework.html', 
                                homework=homework,
                                classes=classes,
                                subjects=subjects,
                                selected_class=class_name,
                                selected_subject=subject)
        
        homework = conn.execute('SELECT * FROM homework ORDER BY upload_date DESC LIMIT 10').fetchall()
        classes = conn.execute('SELECT DISTINCT class_name FROM homework ORDER BY class_name').fetchall()
        subjects = conn.execute('SELECT DISTINCT subject FROM homework ORDER BY subject').fetchall()
        
        return render_template('homework.html',
                            homework=homework,
                            classes=classes,
                            subjects=subjects,
                            selected_class='all',
                            selected_subject='all')
    finally:
        conn.close()

@app.route('/admin/blocked-ips')
@admin_required
def blocked_ips():
    try:
        with open('failed_attempts.json', 'r') as f:
            blocked = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        blocked = {}
    
    # Count IPs with 3+ attempts
    blocked_count = sum(1 for data in blocked.values() if data.get('attempts', 0) >= 3)
    
    return render_template('admin/blocked_ips.html', 
                         blocked_ips=blocked,
                         blocked_ips_count=blocked_count)

@app.route('/admin/unblock-ip/<ip>')
@admin_required
def unblock_ip(ip):
    try:
        with open('failed_attempts.json', 'r') as f:
            blocked = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        blocked = {}
    
    if ip in blocked:
        blocked.pop(ip)
        try:
            with open('failed_attempts.json', 'w') as f:
                json.dump(blocked, f)
            flash(f'Successfully unblocked {ip}', 'success')
        except Exception as e:
            flash(f'Error saving changes: {str(e)}', 'danger')
    else:
        flash('IP/username not found in blocked list', 'warning')
    
    return redirect(url_for('blocked_ips'))

@app.route('/admin/upload_classwork', methods=['GET', 'POST'])
@admin_required
def upload_classwork():
    if request.method == 'POST':
        try:
            class_name = request.form.get('class_name')
            subject = request.form.get('subject')
            title = request.form.get('title')
            description = request.form.get('description')
            due_date = request.form.get('due_date')
            file = request.files['file']

            if not all([class_name, subject, title, file]):
                flash('Please fill all required fields', 'danger')
                return redirect(url_for('upload_classwork'))

            if file and allowed_file(file.filename):
                filename = secure_filename(f"{class_name}_{subject}_{title}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                # Upload to Google Drive
                drive_file = upload_to_drive(file_path, filename)
                drive_file_id = drive_file['id'] if drive_file else None

                conn = get_db_connection()
                conn.execute(
                    '''INSERT INTO classwork 
                    (class_name, subject, title, description, filename, upload_date, due_date, drive_file_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                    (class_name, subject, title, description, filename, 
                     datetime.now().strftime('%Y-%m-%d %H:%M:%S'), due_date, drive_file_id)
                )
                conn.commit()
                conn.close()

                # Remove local file after upload to Drive
                if drive_file_id and os.path.exists(file_path):
                    os.remove(file_path)

                flash('Class work uploaded successfully!', 'success')
                return redirect(url_for('upload_classwork'))  # Stay on same page after success
            else:
                flash('Invalid file type. Allowed formats: PDF, DOC, DOCX, PPT, PPTX', 'danger')
                return redirect(url_for('upload_classwork'))
        except Exception as e:
            print(f"Error uploading class work: {e}")
            flash(f'An error occurred while uploading class work: {str(e)}', 'danger')
            return redirect(url_for('upload_classwork'))

    return render_template('admin/upload_classwork.html')

@app.route('/admin/upload_homework', methods=['GET', 'POST'])
@admin_required
def upload_homework():
    if request.method == 'POST':
        try:
            class_name = request.form.get('class_name')
            subject = request.form.get('subject')
            title = request.form.get('title')
            description = request.form.get('description')
            due_date = request.form.get('due_date')
            file = request.files['file']

            if not all([class_name, subject, title, due_date, file]):
                flash('Please fill all required fields', 'danger')
                return redirect(url_for('upload_homework'))

            if file and allowed_file(file.filename):
                filename = secure_filename(f"{class_name}_{subject}_{title}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                # Upload to Google Drive
                drive_file = upload_to_drive(file_path, filename)
                drive_file_id = drive_file['id'] if drive_file else None

                conn = get_db_connection()
                conn.execute(
                    '''INSERT INTO homework 
                    (class_name, subject, title, description, filename, upload_date, due_date, drive_file_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                    (class_name, subject, title, description, filename, 
                     datetime.now().strftime('%Y-%m-%d %H:%M:%S'), due_date, drive_file_id)
                )
                conn.commit()
                conn.close()

                # Remove local file after upload to Drive
                if drive_file_id and os.path.exists(file_path):
                    os.remove(file_path)

                flash('Homework uploaded successfully!', 'success')
                return redirect(url_for('upload_homework'))  # Stay on same page after success
            else:
                flash('Invalid file type. Allowed formats: PDF, DOC, DOCX', 'danger')
                return redirect(url_for('upload_homework'))
        except Exception as e:
            print(f"Error uploading homework: {e}")
            flash(f'An error occurred while uploading homework: {str(e)}', 'danger')
            return redirect(url_for('upload_homework'))

    return render_template('admin/upload_homework.html')

@app.route('/books')
@login_required
def books():
    conn = get_db_connection()
    try:
        books = conn.execute('SELECT * FROM books ORDER BY upload_date DESC').fetchall()
        return render_template('books.html', books=books)
    finally:
        conn.close()

@app.route('/admin/upload_book', methods=['GET', 'POST'])
@admin_required
def upload_book():
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            author = request.form.get('author')
            subject = request.form.get('subject')
            class_name = request.form.get('class_name')
            file = request.files['file']

            if not all([title, file]):
                flash('Please fill all required fields', 'danger')
                return redirect(url_for('upload_book'))

            if file and allowed_file(file.filename, allowed_extensions=['pdf']):
                filename = secure_filename(f"{title.replace(' ', '_')}_{file.filename}")
                upload_folder = app.config['UPLOAD_FOLDER']
                
                os.makedirs(upload_folder, exist_ok=True)
                file_path = os.path.join(upload_folder, filename)
                file.save(file_path)

                # Upload to Google Drive
                drive_file = upload_to_drive(file_path, filename)
                drive_file_id = drive_file['id'] if drive_file else None

                conn = get_db_connection()
                conn.execute(
                    '''INSERT INTO books 
                    (title, author, subject, class_name, filename, upload_date, drive_file_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (title, author, subject, class_name, filename, 
                     datetime.now().strftime('%Y-%m-%d %H:%M:%S'), drive_file_id)
                )
                conn.commit()
                conn.close()

                # Remove local file after upload to Drive
                if drive_file_id and os.path.exists(file_path):
                    os.remove(file_path)

                flash('Book uploaded successfully!', 'success')
                return redirect(url_for('upload_book'))  # Stay on same page after success
            else:
                flash('Invalid file type. Only PDF files are allowed.', 'danger')
                return redirect(url_for('upload_book'))
        except Exception as e:
            print(f"Error uploading book: {e}")
            flash(f'An error occurred while uploading book: {str(e)}', 'danger')
            return redirect(url_for('upload_book'))

    return render_template('admin/upload_book.html')

@app.route('/admin/approved-users')
@admin_required
def approved_users():
    # Load users from users.json
    with open('users.json') as f:
        users = json.load(f)
    
    # Filter approved users (assuming status field exists)
    approved_users = [user for user in users if user.get('status') == 'approved']
    
    return render_template('admin/approved_users.html', users=approved_users)

@app.route('/admin/pending-users')
@admin_required
def pending_users():
    pending_users = load_json(PENDING_FILE)
    return render_template('admin/pending_users.html', users=pending_users)

@app.route('/admin/approve-user/<username>')
@admin_required
def approve_user(username):
    try:
        pending_users = load_json(PENDING_FILE)
        user = next((u for u in pending_users if u['username'] == username), None)
        
        if user:
            # Remove from pending
            pending_users = [u for u in pending_users if u['username'] != username]
            save_json(pending_users, PENDING_FILE)
            
            # Add to approved users
            approved_users = load_json(USERS_FILE)
            approved_users.append(user)
            save_json(approved_users, USERS_FILE)
            
            flash(f'User {username} approved successfully', 'success')
        else:
            flash('User not found in pending list', 'danger')
    except Exception as e:
        print(f"Error approving user: {e}")
        flash('Failed to approve user', 'danger')
    
    return redirect(url_for('pending_users'))

@app.route('/admin/decline-user/<username>', methods=['GET', 'POST'])
@admin_required
def decline_user(username):
    if request.method == 'POST':
        reason = request.form.get('reason', 'No reason provided')
        try:
            pending_users = load_json(PENDING_FILE)
            user = next((u for u in pending_users if u['username'] == username), None)
            
            if user:
                # Remove from pending
                pending_users = [u for u in pending_users if u['username'] != username]
                save_json(pending_users, PENDING_FILE)
                
                # Add to declined with reason
                user['reason'] = reason
                declined_users = load_json(DECLINED_FILE)
                declined_users.append(user)
                save_json(declined_users, DECLINED_FILE)
                
                flash(f'User {username} declined with reason: {reason}', 'success')
            else:
                flash('User not found in pending list', 'danger')
        except Exception as e:
            print(f"Error declining user: {e}")
            flash('Failed to decline user', 'danger')
        
        return redirect(url_for('pending_users'))
    
    return render_template('admin/decline_user.html', username=username)

@app.route('/admin/feedback/<int:id>/resolve', methods=['POST'])
@admin_required
def resolve_feedback(id):
    try:
        notes = request.form.get('notes', '')
        conn = get_db_connection()
        conn.execute(
            'UPDATE feedback SET status = ?, admin_notes = ? WHERE id = ?',
            ('resolved', notes, id))
        conn.commit()
        conn.close()
        flash('Feedback marked as resolved', 'success')
    except Exception as e:
        print(f"Error resolving feedback: {e}")
        flash('Failed to resolve feedback', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/notifications', methods=['GET', 'POST'])
@admin_required
def admin_notifications():
    conn = get_db_connection()
    try:
        if request.method == 'POST':
            title = request.form.get('title')
            content = request.form.get('content')
            is_pinned = 1 if request.form.get('is_pinned') else 0
            date_posted = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            conn.execute(
                'INSERT INTO notifications (title, content, date_posted, is_pinned) VALUES (?, ?, ?, ?)',
                (title, content, date_posted, is_pinned))
            conn.commit()
            flash('Notification added successfully!', 'success')
        
        notifications = conn.execute('SELECT * FROM notifications ORDER BY date_posted DESC').fetchall()
        return render_template('admin/notifications.html', notifications=notifications)
    finally:
        conn.close()

@app.route('/admin/delete_notification/<int:id>')
@admin_required
def delete_notification(id):
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM notifications WHERE id = ?', (id,))
        conn.commit()
        flash('Notification deleted successfully!', 'success')
    finally:
        conn.close()
    return redirect(url_for('admin_notifications'))

@app.route('/admin/toggle-pin/<int:id>')
@admin_required
def toggle_pin_notification(id):
    conn = get_db_connection()
    try:
        notification = conn.execute('SELECT * FROM notifications WHERE id = ?', (id,)).fetchone()
        if notification:
            new_status = 0 if notification['is_pinned'] else 1
            conn.execute('UPDATE notifications SET is_pinned = ? WHERE id = ?', (new_status, id))
            conn.commit()
            flash('Notification pin status updated', 'success')
        else:
            flash('Notification not found', 'danger')
    except Exception as e:
        print(f"Error toggling pin status: {e}")
        flash('Failed to update pin status', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('admin_notifications'))

@app.route('/admin/upload_syllabus', methods=['GET', 'POST'])
@admin_required
def upload_syllabus():
    if request.method == 'POST':
        try:
            required_fields = ['class_name', 'year', 'month', 'exam_name', 'subject']
            if not all(request.form.get(field) for field in required_fields) or not request.files.get('file'):
                flash('Please fill all required fields', 'danger')
                return redirect(url_for('upload_syllabus'))
            
            file = request.files['file']
            if file and allowed_file(file.filename, allowed_extensions=['pdf', 'doc', 'docx']):
                filename = secure_filename(
                    f"syllabus_{request.form['class_name']}_{request.form['subject']}_{request.form['exam_name']}_{file.filename}"
                )
                upload_folder = app.config['UPLOAD_FOLDER']
                
                os.makedirs(upload_folder, exist_ok=True)
                file_path = os.path.join(upload_folder, filename)
                file.save(file_path)
                
                # Upload to Google Drive
                drive_file = upload_to_drive(file_path, filename)
                drive_file_id = drive_file['id'] if drive_file else None
                
                conn = get_db_connection()
                conn.execute(
                    '''INSERT INTO syllabus 
                    (class_name, year, month, exam_name, subject, filename, upload_date, drive_file_id) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                    (
                        request.form['class_name'],
                        request.form['year'],
                        request.form['month'],
                        request.form['exam_name'],
                        request.form['subject'],
                        filename,
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        drive_file_id
                    )
                )
                conn.commit()
                conn.close()
                
                # Remove local file after upload to Drive
                if drive_file_id and os.path.exists(file_path):
                    os.remove(file_path)
                
                flash('Syllabus uploaded successfully!', 'success')
                return redirect(url_for('upload_syllabus'))  # Stay on same page
            else:
                flash('Invalid file type. Only PDF, DOC, and DOCX files are allowed.', 'danger')
                return redirect(url_for('upload_syllabus'))
        except Exception as e:
            print(f"Error uploading syllabus: {str(e)}")
            flash(f'An error occurred while uploading syllabus: {str(e)}', 'danger')
            return redirect(url_for('upload_syllabus'))
    
    return render_template('admin/upload_syllabus.html')

@app.route('/admin/delete_syllabus/<int:id>', methods=['POST'])
@admin_required
def delete_syllabus(id):
    try:
        conn = get_db_connection()
        syllabus = conn.execute('SELECT filename, drive_file_id FROM syllabus WHERE id = ?', (id,)).fetchone()
        if not syllabus:
            flash('Syllabus not found', 'danger')
            return redirect(url_for('syllabus'))
        
        # Delete from Google Drive if exists
        if syllabus['drive_file_id']:
            delete_from_drive(syllabus['drive_file_id'])
        
        # Delete local file if exists
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], syllabus['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        conn.execute('DELETE FROM syllabus WHERE id = ?', (id,))
        conn.commit()
        conn.close()
        
        flash('Syllabus deleted successfully!', 'success')
    except Exception as e:
        print(f"Error deleting syllabus: {e}")
        flash('An error occurred while deleting syllabus', 'danger')
    
    return redirect(url_for('syllabus'))

@app.route('/admin/upload_document', methods=['GET', 'POST'])
@admin_required
def upload_document():
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                flash('No file selected', 'danger')
                return redirect(url_for('upload_document'))
            
            file = request.files['file']
            name = request.form.get('name')
            category = request.form.get('category')
            
            if not all([name, category, file]):
                flash('Please fill all required fields', 'danger')
                return redirect(url_for('upload_document'))
            
            if file.filename == '':
                flash('No selected file', 'danger')
                return redirect(url_for('upload_document'))
            
            allowed_extensions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png']
            if file and allowed_file(file.filename, allowed_extensions=allowed_extensions):
                filename = secure_filename(f"doc_{category.replace(' ', '_')}_{name.replace(' ', '_')}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # Upload to Google Drive
                drive_file = upload_to_drive(file_path, filename)
                drive_file_id = drive_file['id'] if drive_file else None
                
                conn = get_db_connection()
                conn.execute(
                    'INSERT INTO documents (name, category, filename, upload_date, drive_file_id) VALUES (?, ?, ?, ?, ?)',
                    (name, category, filename, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), drive_file_id)
                )
                conn.commit()
                conn.close()
                
                # Remove local file after upload to Drive
                if drive_file_id and os.path.exists(file_path):
                    os.remove(file_path)
                
                flash('Document uploaded successfully', 'success')
                return redirect(url_for('upload_document'))  # Stay on same page
            else:
                flash('Allowed file types are PDF, DOC, DOCX, XLS, XLSX, JPG, JPEG, PNG', 'danger')
                return redirect(url_for('upload_document'))
        except Exception as e:
            print(f"Error uploading document: {str(e)}")
            flash(f'An error occurred while uploading document: {str(e)}', 'danger')
            return redirect(url_for('upload_document'))
    
    return render_template('admin/upload_document.html')

@app.route('/admin/delete_document/<int:id>', methods=['POST'])
@admin_required
def delete_document(id):
    try:
        conn = get_db_connection()
        document = conn.execute('SELECT filename, drive_file_id FROM documents WHERE id = ?', (id,)).fetchone()
        if not document:
            flash('Document not found', 'danger')
            return redirect(url_for('documents'))
        
        # Delete from Google Drive if exists
        if document['drive_file_id']:
            delete_from_drive(document['drive_file_id'])
        
        # Delete local file if exists
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        conn.execute('DELETE FROM documents WHERE id = ?', (id,))
        conn.commit()
        conn.close()
        
        flash('Document deleted successfully!', 'success')
    except Exception as e:
        print(f"Error deleting document: {e}")
        flash('An error occurred while deleting document', 'danger')
    
    return redirect(url_for('documents'))

@app.route('/admin/change_password', methods=['GET', 'POST'])
@admin_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([current_password, new_password, confirm_password]):
            flash('Please fill all fields', 'danger')
            return redirect(url_for('change_password'))
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('change_password'))
        
        conn = get_db_connection()
        try:
            admin = conn.execute('SELECT * FROM admin WHERE username = ?', (session['admin_username'],)).fetchone()
            
            if not check_password_hash(admin['password'], current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('change_password'))
            
            conn.execute(
                'UPDATE admin SET password = ? WHERE username = ?',
                (generate_password_hash(new_password), session['admin_username']))
            conn.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        finally:
            conn.close()
    
    return render_template('admin/change_password.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

# Static file serving
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/check_username', methods=['POST'])
def check_username():
    data = request.get_json()
    username = data.get('username')

    with open('users.json', 'r') as f:
        users = json.load(f)

    for user in users:
        if user['username'].lower() == username.lower():
            return jsonify({'available': False})  # Username taken

    return jsonify({'available': True})  # Username is available


if __name__ == '__main__':
    # Create required files if they don't exist
    for file in [USERS_FILE, PENDING_FILE, DECLINED_FILE]:
        if not os.path.exists(file):
            save_json([], file)
    
    # Create upload folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    app.run(host="0.0.0.0", port=5000, debug=True)
