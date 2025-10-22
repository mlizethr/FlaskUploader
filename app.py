# app.py
import os
import io
import socket
from flask import Flask, request, jsonify
from smb.SMBConnection import SMBConnection
from werkzeug.utils import secure_filename
from flask_cors import CORS
import base64
import traceback

app = Flask(__name__)
CORS(app)

# config via env vars
SMB_SERVER = os.environ.get("SMB_SERVER", "joaquincruz.com")
SMB_SHARE  = os.environ.get("SMB_SHARE", "Archivos-Medicos")
SMB_PORTS  = [int(x) for x in os.environ.get("SMB_PORTS", "445,139").split(",")]  # try 445 then 139
SMB_REMOTE_NAME = os.environ.get("SMB_REMOTE_NAME", SMB_SERVER)
SMB_DOMAIN = os.environ.get("SMB_DOMAIN", "")

ALLOWED_EXTENSIONS = {'pdf','jpg','jpeg','png','txt'}

def allowed_file(filename):
    return '.' in filename and len(filename.rsplit('.', 1)[1]) > 0

def test_tcp_connect(host, port, timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True, None
    except Exception as e:
        return False, str(e)

def try_smb_connect(username, password, port, timeout=10):
    """
    Try to create and connect SMBConnection on a given port.
    Return (conn, None) on success, (None, error_message) on failure.
    """
    try:
        client_name = "flask_app"
        conn = SMBConnection(username, password, client_name, SMB_REMOTE_NAME, domain=SMB_DOMAIN, use_ntlm_v2=True)
        # SMBConnection.connect may raise SystemExit in some libs if protocol not allowed;
        # wrap to prevent container exit.
        try:
            ok = conn.connect(SMB_SERVER, port, timeout=timeout)
        except SystemExit as se:
            # capture and translate to string
            return None, f"SystemExit from SMB library: {se}"
        except Exception as e:
            return None, f"connect() exception: {repr(e)}"
        if not ok:
            try:
                conn.close()
            except Exception:
                pass
            return None, "connect() returned False"
        return conn, None
    except Exception as e:
        return None, f"SMBConnection init failed: {repr(e)}"

@app.route('/', methods=['GET'])
def index():
    return jsonify({"message": "Flask uploader alive. POST /upload with Basic auth and form field 'file'."})

@app.route('/debug_smb', methods=['GET'])
def debug_smb():
    """
    Quick debug endpoint. Returns TCP reachability to SMB_SERVER on ports and DNS.
    Usage: GET /debug_smb
    """
    out = {"server": SMB_SERVER, "share": SMB_SHARE, "ports_tested": []}
    # DNS resolution test
    try:
        ip = socket.gethostbyname(SMB_SERVER)
        out["resolved_ip"] = ip
    except Exception as e:
        out["resolved_ip_error"] = str(e)
    for p in SMB_PORTS:
        ok, err = test_tcp_connect(SMB_SERVER, p)
        out["ports_tested"].append({"port": p, "open": ok, "error": err})
    return jsonify(out)

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        # parse auth
        auth = request.authorization
        if not auth:
            # try manual Basic header
            ah = request.headers.get("Authorization")
            if ah and ah.startswith("Basic "):
                try:
                    decoded = base64.b64decode(ah.split(" ",1)[1]).decode("utf-8")
                    u,p = decoded.split(":",1)
                    auth = type("A", (), {"username": u, "password": p})
                except Exception as e:
                    return jsonify({"error": "Invalid Authorization header", "detail": str(e)}), 401
            else:
                return jsonify({"error":"Missing credentials"}), 401

        username = auth.username
        password = auth.password

        if 'file' not in request.files:
            return jsonify({"error":"No file part (field 'file')"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error":"Empty filename"}), 400
        if not allowed_file(file.filename):
            return jsonify({"error":"File type not allowed"}), 400

        filename = secure_filename(file.filename)
        file_bytes = io.BytesIO(file.read())
        file_bytes.seek(0)

        # Try ports in order and capture errors
        port_errors = []
        last_smb_error = None
        for port in SMB_PORTS:
            # quick TCP-level test first
            ok, terr = test_tcp_connect(SMB_SERVER, port)
            port_errors.append({"port": port, "tcp_ok": ok, "tcp_err": terr})
            if not ok:
                last_smb_error = f"TCP connect failed on port {port}: {terr}"
                continue
            # try SMB auth/connect
            conn, err = try_smb_connect(username, password, port)
            if conn is None:
                last_smb_error = f"SMB connect failed on port {port}: {err}"
                continue
            # connected -> try to store file
            try:
                # ensure stream at start
                try:
                    file_bytes.seek(0)
                except Exception:
                    pass
                conn.storeFile(SMB_SHARE, filename, file_bytes)
                conn.close()
                return jsonify({
                	    "success": f"File {filename} uploaded to SMB on port {port}",
	    	    "filename": filename
		}), 200

            except Exception as e:
                last_smb_error = f"storeFile failed on port {port}: {repr(e)}"
                try:
                    conn.close()
                except Exception:
                    pass
                continue

        # If we get here, all ports failed
        return jsonify({
            "error": "All SMB attempts failed",
            "last_error": last_smb_error,
            "port_checks": port_errors
        }), 502

    except Exception as e:
        tb = traceback.format_exc()
        return jsonify({"error": "Unexpected server error", "detail": str(e), "traceback": tb}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
