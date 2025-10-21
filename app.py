from flask import Flask, request, jsonify
from smb.SMBConnection import SMBConnection
from werkzeug.utils import secure_filename
import io

app = Flask(__name__)

ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'png', 'txt'}
SMB_SERVER = 'joaquincruz.com'
SMB_SHARE = 'Archivos-Medicos'

def allowed_file(filename):
    return '.' in filename and '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    auth = request.authorization
    if not auth:
        return jsonify({"error": "Unauthorized"}), 401

    username = auth.username
    password = auth.password

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    filename = secure_filename(file.filename)
    file_bytes = io.BytesIO(file.read())

    # Connect to SMB dynamically
    conn = SMBConnection(username, password, "flaskclient", SMB_SERVER, use_ntlm_v2=True)
    if not conn.connect(SMB_SERVER, 139):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        conn.storeFile(SMB_SHARE, filename, file_bytes)
        return jsonify({"success": f"File {filename} uploaded to SMB"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
