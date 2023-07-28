from flask import Flask, make_response, render_template, request, redirect, url_for, send_from_directory, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import timedelta
import os
from PIL import Image
from io import BytesIO
import sqlite3
import zipfile

MAX_SIZE = (800, 800)

def resize_image(image_path):
    img = Image.open(image_path)
    img.thumbnail(MAX_SIZE)
    img.save(image_path)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

'''# Login Manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
'''
# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

'''@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required.')
            return redirect(url_for('signup'))

        user = User.query.filter_by(username=username).first()

        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('signup'))

        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully.')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required.')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        if user is None or not check_password_hash(user.password, password):
            flash('Invalid credentials.')
            return redirect(url_for('login'))

        login_user(user)
        flash('Logged in successfully.')
        return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('index'))

# The following changes are needed for the upload_image route
@app.route('/upload', methods=['POST'])
@login_required
def upload_new_image():
    if not current_user.is_admin:
        flash('You do not have permission to upload images.')
        return redirect(url_for('index'))

    if 'files' not in request.files:
        return redirect(request.url)

    files = request.files.getlist('files')

    # Check if any files were uploaded
    if not files:
        return redirect(request.url)

    saved_files = []

    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            saved_files.append(filename)

    if saved_files:
        conn = sqlite3.connect('images.db')
        cursor = conn.cursor()
        cursor.executemany("INSERT INTO images (filename) VALUES (?)", [(filename,) for filename in saved_files])
        conn.commit()

    return redirect(url_for('index'))'''

@app.route('/')
def index():
    conn = sqlite3.connect('images.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM images")
    images = cursor.fetchall()
    return render_template('index.html', images=images)

@app.route('/upload', methods=['POST'])
def upload_image():
    if 'files' not in request.files:
        return redirect(request.url)

    files = request.files.getlist('files')

    # Check if any files were uploaded
    if not files:
        return redirect(request.url)

    saved_files = []

    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            saved_files.append(filename)

    if saved_files:
        conn = sqlite3.connect('images.db')
        cursor = conn.cursor()
        cursor.executemany("INSERT INTO images (filename) VALUES (?)", [(filename,) for filename in saved_files])
        conn.commit()

    return redirect(url_for('index'))

@app.route('/delete/<path:filename>', methods=['POST'])
def delete_image(filename):
    conn = sqlite3.connect('images.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM images WHERE filename=?", (filename,))
    conn.commit()
    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return redirect(url_for('index'))

@app.route('/delete-all', methods=['POST'])
def delete_all():
    # Remove all image files from the UPLOAD_FOLDER directory
    for root, dirs, files in os.walk(app.config['UPLOAD_FOLDER']):
        for filename in files:
            file_path = os.path.join(root, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)

    # Delete all records from the images table in the database
    conn = sqlite3.connect('images.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM images")
    conn.commit()

    # Redirect the user back to the index page
    return redirect(url_for('index'))

@app.route('/download-all')
def download_all():
    # Create a ZIP file containing all uploaded images
    zip_filename = 'all_images.zip'
    zip_path = os.path.join(app.config['UPLOAD_FOLDER'], zip_filename)

    with zipfile.ZipFile(zip_path, 'w') as zipf:
        for root, dirs, files in os.walk(app.config['UPLOAD_FOLDER']):
            for filename in files:
                if allowed_file(filename):
                    file_path = os.path.join(root, filename)
                    zipf.write(file_path, os.path.basename(file_path))

    # Send the ZIP file to the user
    response = make_response(send_file(zip_path, mimetype='application/zip'))
    response.headers['Content-Disposition'] = f'attachment; filename="{zip_filename}"'
    return response

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/download/<path:filename>')
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.isfile(file_path):
        return redirect(url_for('index'))
    file_extension = filename.rsplit('.', 1)[1].lower()
    if file_extension == 'gif':
        mimetype = 'image/gif'
    elif file_extension == 'webp':
        mimetype = 'image/webp'
    elif file_extension == 'jpg' or file_extension == 'jpeg':
        mimetype = 'image/jpeg'
    else:
        mimetype = 'image/png'

    # If the file is a WebP image, convert it to PNG before sending it
    if file_extension == 'webp':
        img = Image.open(file_path)
        img_byte_arr = BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr.seek(0)
        response = make_response(send_file(img_byte_arr, mimetype='image/png', as_attachment=True, download_name=f"{filename.rsplit('.', 1)[0]}.png"))
    else:
        response = make_response(send_file(file_path, mimetype=mimetype, as_attachment=True, download_name=filename))

    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response

@app.route('/set-theme', methods=['POST'])
def set_theme():
    theme = request.form['theme']
    if theme == 'dark':
        response = make_response(redirect(url_for('index')))
        response.set_cookie('theme', 'dark', max_age=365 * 24 * 60 * 60)
    else:
        response = make_response(redirect(url_for('index')))
        response.set_cookie('theme', 'light', max_age=365 * 24 * 60 * 60)
    return response

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
with app.app_context():
    db.create_all()  # Create the database tables      # Create the database tables
    app.run(debug=True)