from flask import Flask, request, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from werkzeug.utils import secure_filename
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'txt', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            file_path TEXT,
            description TEXT
        )
    ''')
    conn.commit()
    conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def index():
    # Fetch all posts from the database
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM posts")
    posts = c.fetchall()
    conn.close()
    return render_template('posts.html', posts=posts)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        username = request.form['username']
        description = request.form['description']
        file = request.files['file']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Save to database
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO posts (username, file_path, description) VALUES (?, ?, ?)",
                      (username, file_path, description))
            conn.commit()
            conn.close()

            flash('File uploaded successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid file type.', 'error')

    return render_template('upload.html')

@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    init_db()
    app.run(debug=True)

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    conn.commit()
    conn.close()

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            flash('Account created successfully! You can log in now.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
        finally:
            conn.close()

    return render_template('signup.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')

# Dashboard route (requires login)
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return f"<h1>Welcome, {session['username']}!</h1><br><a href='/logout'>Logout</a>"
    else:
        flash('You need to log in first.', 'error')
        return redirect(url_for('login'))

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
