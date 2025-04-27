from flask import Flask, render_template, request, send_file, flash, redirect, url_for
import os, io
from PIL import Image
from PyPDF2 import PdfReader, PdfWriter
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'
for d in (UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER):
    os.makedirs(d, exist_ok=True)

@app.route('/encrypt', methods=['GET', 'POST'])
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
        return send_file(out_stream,
                         as_attachment=True,
                         download_name=name,
                         mimetype='application/pdf')

    return render_template('decrypt.html')

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
