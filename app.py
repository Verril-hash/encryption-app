import streamlit as st
import os
import io
from PIL import Image
from PyPDF2 import PdfReader, PdfWriter

# Set page config for better UI
st.set_page_config(page_title="PDF Encryption/Decryption App", layout="wide")

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Create directories (for local testing; limited use in Streamlit Cloud)
UPLOAD_FOLDER = 'Uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'
for d in (UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER):
    os.makedirs(d, exist_ok=True)

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Home", "Encrypt PDF", "Decrypt PDF"])

if page == "Home":
    st.title("Welcome to the PDF Encryption/Decryption App")
    st.write("Use this app to:")
    st.write("- **Encrypt**: Convert an image (PNG/JPG) to an encrypted PDF.")
    st.write("- **Decrypt**: Unlock an encrypted PDF with a password.")
    st.write("Select an option from the sidebar to get started.")

elif page == "Encrypt PDF":
    st.title("Encrypt PDF from Image")
    st.write("Upload a PNG or JPG image and set a password to create an encrypted PDF.")

    # File uploader and password input
    img_file = st.file_uploader("Upload Image", type=ALLOWED_EXTENSIONS)
    password = st.text_input("Enter Password for Encryption", type="password")

    if st.button("Encrypt"):
        if not img_file:
            st.error("No file uploaded.")
        elif not password:
            st.error("Please enter a password.")
        elif img_file and allowed_file(img_file.name):
            try:
                # Open and convert image to PDF
                img = Image.open(img_file).convert('RGB')
                pdf_bytes = io.BytesIO()
                img.save(pdf_bytes, format='PDF')
                pdf_bytes.seek(0)

                # Encrypt the PDF
                reader = PdfReader(pdf_bytes)
                writer = PdfWriter()
                for page in reader.pages:
                    writer.add_page(page)

                writer.encrypt(user_password=password, owner_password=None, use_128bit=True)

                encrypted_output = io.BytesIO()
                writer.write(encrypted_output)
                encrypted_output.seek(0)

                # Provide download button
                st.success("PDF encrypted successfully!")
                st.download_button(
                    label="Download Encrypted PDF",
                    data=encrypted_output,
                    file_name="encrypted.pdf",
                    mime="application/pdf"
                )
            except Exception as e:
                st.error(f"Error processing image: {str(e)}")
        else:
            st.error("Invalid file type. Please upload a PNG or JPG image.")

elif page == "Decrypt PDF":
    st.title("Decrypt PDF")
    st.write("Upload an encrypted PDF and enter its password to decrypt.")

    # File uploader and password input
    pdf_file = st.file_uploader("Upload Encrypted PDF", type="pdf")
    password = st.text_input("Enter Password for Decryption", type="password")

    if st.button("Decrypt"):
        if not pdf_file:
            st.error("Please upload a PDF file.")
        elif not password:
            st.error("Please enter a password.")
        else:
            try:
                pdf_stream = io.BytesIO(pdf_file.read())
                reader = PdfReader(pdf_stream)

                if not reader.is_encrypted:
                    st.error("This PDF is not encrypted.")
                else:
                    try:
                        reader.decrypt(password)
                    except Exception:
                        st.error("Wrong password or corrupted file.")
                        st.stop()

                    writer = PdfWriter()
                    for page in reader.pages:
                        writer.add_page(page)

                    out_stream = io.BytesIO()
                    writer.write(out_stream)
                    out_stream.seek(0)

                    # Provide download button
                    st.success("PDF decrypted successfully!")
                    st.download_button(
                        label="Download Decrypted PDF",
                        data=out_stream,
                        file_name=f"decrypted_{pdf_file.name}",
                        mime="application/pdf"
                    )
            except Exception as e:
                st.error(f"Error processing PDF: {str(e)}")