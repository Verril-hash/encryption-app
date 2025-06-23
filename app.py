from flask import Flask, render_template, request, send_file, flash, redirect, url_for, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
from PyPDF2 import PdfReader, PdfWriter
import os, io
from stegano import lsb
from datetime import datetime, UTC
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Activity Model
class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'
for d in (UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER):
    os.makedirs(d, exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        user = User(username=username, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('landing'))

@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt_pdf():
    if request.method == 'POST':
        if 'file' not in request.files or 'password' not in request.form:
            flash("No file or password provided.")
            return redirect(url_for('encrypt_pdf'))
        
        img_file = request.files['file']
        password = request.form['password']

        if img_file.filename == '':
            flash("No selected file.")
            return redirect(url_for('encrypt_pdf'))

        if img_file and allowed_file(img_file.filename):
            try:
                img = Image.open(img_file.stream).convert('RGB')
                pdf_bytes = io.BytesIO()
                img.save(pdf_bytes, format='PDF')
                pdf_bytes.seek(0)

                # Now encrypt the PDF
                reader = PdfReader(pdf_bytes)
                writer = PdfWriter()
                for page in reader.pages:
                    writer.add_page(page)

                writer.encrypt(user_password=password, owner_password=None, use_128bit=True)

                encrypted_output = io.BytesIO()
                writer.write(encrypted_output)
                encrypted_output.seek(0)

                # Log activity with timestamp
                activity = Activity(user_id=current_user.id, filename="encrypted.pdf", timestamp=datetime.utcnow(), status="Encrypted")
                db.session.add(activity)
                db.session.commit()

                return send_file(encrypted_output,
                                 as_attachment=True,
                                 download_name="encrypted.pdf",
                                 mimetype='application/pdf')
            except Exception as e:
                flash(f"Error processing image: {str(e)}")
                return redirect(url_for('encrypt_pdf'))
        else:
            flash("Invalid file type. Please upload a PNG or JPG image.")
            return redirect(url_for('encrypt_pdf'))
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt_pdf():
    if request.method == 'POST':
        upload = request.files.get('file')
        password = request.form.get('password', '')
        if not upload or not password:
            flash("Please upload an encrypted PDF and enter its password.")
            return redirect(url_for('decrypt_pdf'))
        pdf_stream = io.BytesIO(upload.read())
        reader = PdfReader(pdf_stream)
        if not reader.is_encrypted:
            flash("This PDF is not encrypted.")
            return redirect(url_for('decrypt_pdf'))
        try:
            reader.decrypt(password)
        except Exception:
            flash("Wrong password or corrupted file.")
            return redirect(url_for('decrypt_pdf'))
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        out_stream = io.BytesIO()
        writer.write(out_stream)
        out_stream.seek(0)
        name = 'decrypted_' + upload.filename
        activity = Activity(user_id=current_user.id, filename=name, timestamp=datetime.utcnow(), status="Decrypted")
        db.session.add(activity)
        db.session.commit()
        return send_file(out_stream, as_attachment=True, download_name=name, mimetype='application/pdf')
    return render_template('decrypt.html')

# Custom LSB functions with end marker
END_MARKER = b'END'  # Unique sequence to mark the end of data

def custom_hide(image_path, data):
    img = Image.open(image_path).convert('RGB')
    width, height = img.size
    # Append end marker to data
    data_with_marker = data + END_MARKER
    binary_data = ''.join(format(b, '08b') for b in data_with_marker)
    if len(binary_data) > width * height * 3:  # 3 channels (RGB)
        raise ValueError(f"Data too large: {len(binary_data)} bits exceeds {width * height * 3} bits")
    pixels = list(img.getdata())
    data_index = 0
    logger.debug(f"Embedding data length: {len(binary_data)} bits")
    for i in range(len(pixels)):
        if data_index >= len(binary_data):
            logger.debug(f"Embedding complete at pixel {i}, data_index: {data_index}")
            break
        pixel = list(pixels[i])
        for j in range(3):  # RGB channels
            if data_index < len(binary_data):
                bit = int(binary_data[data_index])
                pixel[j] = (pixel[j] & ~1) | bit
                logger.debug(f"Pixel {i}, Channel {j}, Bit {data_index}: {bit}")
                data_index += 1
        pixels[i] = tuple(pixel)
    img.putdata(pixels)
    return img

def custom_reveal(image_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())
    binary_data = ''
    max_bits = min(img.width * img.height * 3, 256 * 8)  # Limit to 256 bytes (2048 bits) as a safety net
    for i, pixel in enumerate(pixels):
        if len(binary_data) >= max_bits:
            logger.warning(f"Reached maximum bit capacity: {max_bits}")
            break
        for j, value in enumerate(pixel[:3]):  # RGB channels
            bit = value & 1
            binary_data += str(bit)
            # Check for end marker in bytes
            if len(binary_data) >= 24:  # Minimum to detect 'END' (3 bytes * 8)
                byte_data = bytearray(int(binary_data[k:k+8], 2) for k in range(0, len(binary_data), 8) if k + 8 <= len(binary_data))
                try:
                    end_index = bytes(byte_data).index(END_MARKER)
                    logger.debug(f"End marker found at byte index: {end_index}")
                    binary_data = binary_data[:end_index * 8]  # Trim to last full byte before marker
                    break
                except ValueError:
                    if len(binary_data) >= max_bits:
                        break
        if len(binary_data) >= max_bits:
            break
    logger.debug(f"Extracted binary length: {len(binary_data)} bits")
    # Convert binary to bytes
    byte_data = bytearray()
    for i in range(0, len(binary_data), 8):
        segment = binary_data[i:i+8]
        if len(segment) == 8:
            byte = int(segment, 2)
            byte_data.append(byte)
            if i // 8 < 31:  # Limit logging for readability
                logger.debug(f"Byte {i//8}: {segment} -> {byte} ({chr(byte) if 32 <= byte <= 126 else '.'})")
    logger.debug(f"Extracted byte data length: {len(byte_data)} bytes, Raw Sample: {bytes(byte_data).hex()}")
    return bytes(byte_data)

@app.route('/steganography', methods=['GET', 'POST'])
@login_required
def steganography():
    if request.method == 'POST':
        cover_file = request.files.get('cover')
        data_file = request.files.get('data')
        if not cover_file or not data_file:
            flash("Please upload both cover and data files.")
            return redirect(url_for('steganography'))
        
        if not allowed_file(cover_file.filename):
            flash("Invalid cover file type. Please upload a PNG or JPG image.")
            return redirect(url_for('steganography'))

        # Validate image stream
        try:
            cover_img = Image.open(cover_file.stream)
            cover_file.seek(0)  # Reset stream
            logger.debug(f"Image stream validated, dimensions: {cover_img.width}x{cover_img.height}")
        except Exception as e:
            logger.error(f"Failed to open image stream: {str(e)}")
            flash("Invalid or corrupted image file in stream.")
            return redirect(url_for('steganography'))

        # Calculate approximate capacity
        capacity = (cover_img.width * cover_img.height) // 8  # Theoretical max bytes
        data_size = len(data_file.read())
        data_file.seek(0)  # Reset file pointer
        logger.debug(f"Cover image capacity: {capacity} bytes, Data size: {data_size} bytes")

        if data_size > capacity - len(END_MARKER):  # Account for end marker
            flash(f"Data size ({data_size} bytes) exceeds image capacity ({capacity - len(END_MARKER)} bytes) with end marker. Use a larger cover image.")
            return redirect(url_for('steganography'))

        try:
            # Save files temporarily
            cover_path = os.path.join(UPLOAD_FOLDER, secure_filename(cover_file.filename))
            data_path = os.path.join(UPLOAD_FOLDER, secure_filename(data_file.filename))
            cover_file.save(cover_path)
            data_file.save(data_path)
            logger.debug(f"Files saved: cover at {cover_path}, data at {data_path}, cover size: {os.path.getsize(cover_path)} bytes")

            # Verify file signature
            with open(cover_path, 'rb') as f:
                file_content = f.read(4)
                logger.debug(f"Cover file signature: {file_content.hex()}")
                if not (file_content.startswith(b'\xFF\xD8') or file_content.startswith(b'\x89PNG')):
                    raise ValueError("File is not a valid JPG or PNG.")

            # Read data file as binary
            with open(data_path, 'rb') as f:
                secret_data = f.read()
            logger.debug(f"Data to hide length: {len(secret_data)} bytes, Sample: {secret_data[:100]}...")

            # Hide data with custom function
            stego_image = custom_hide(cover_path, secret_data)
            stego_output = io.BytesIO()
            stego_image.save(stego_output, format='PNG')
            stego_output.seek(0)
            logger.debug(f"Stego image created, pixel count: {stego_image.width * stego_image.height}")

            # Clean up temporary files
            os.remove(cover_path)
            os.remove(data_path)

            # Log activity
            activity = Activity(user_id=current_user.id, filename="stego.png", timestamp=datetime.now(UTC), status="Stego-Created")
            db.session.add(activity)
            db.session.commit()

            return send_file(stego_output, as_attachment=True, download_name="stego.png", mimetype='image/png')
        except Exception as e:
            logger.error(f"Steganography error: {str(e)}")
            flash(f"Error during steganography: {str(e)}")
            return redirect(url_for('steganography'))

    return render_template('steganography.html')

@app.route('/extract', methods=['GET', 'POST'])
@login_required
def extract():
    if request.method == 'POST':
        stego_file = request.files.get('stego')
        if not stego_file:
            flash("Please upload a stego-image.")
            return redirect(url_for('extract'))
        
        try:
            # Save the stego-image temporarily
            stego_path = os.path.join(UPLOAD_FOLDER, secure_filename(stego_file.filename))
            stego_file.save(stego_path)
            logger.debug(f"Stego file saved at {stego_path}, size: {os.path.getsize(stego_path)} bytes")

            # Extract the hidden data with custom function
            secret_data = custom_reveal(stego_path)
            logger.debug(f"Extracted data type: {type(secret_data)}, length: {len(secret_data)}, Sample: {secret_data.hex()}")

            # Clean up temporary file
            os.remove(stego_path)

            # Prepare download as a text file
            original_filename = stego_file.filename.replace('.png', '_extracted.txt')
            output = io.BytesIO()
            output.write(secret_data.decode('utf-8', errors='replace').encode('utf-8'))  # Convert to text
            output.seek(0)
            mimetype = 'text/plain'

            # Ensure the file is not empty
            if not secret_data:
                flash("No data extracted. The stego image may be corrupted or empty.")
                return redirect(url_for('extract'))

            activity = Activity(user_id=current_user.id, filename=original_filename, timestamp=datetime.now(UTC), status="Data Extracted")
            db.session.add(activity)
            db.session.commit()

            return send_file(output, as_attachment=True, download_name=original_filename, mimetype=mimetype)
        except Exception as e:
            logger.error(f"Extraction error: {str(e)}")
            flash(f"Error extracting data: {str(e)}")
            return redirect(url_for('extract'))

    return render_template('extract.html')

@app.route('/activity')
@login_required
def activity():
    activities = Activity.query.filter_by(user_id=current_user.id).all()
    return render_template('activity.html', activities=activities)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/')
def landing():
    return render_template('landing.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))