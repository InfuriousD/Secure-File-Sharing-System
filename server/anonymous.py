import datetime
import os

from flask import Blueprint, request, jsonify, send_file

from config import SERVER_CONFIG
from db import get_db_connection
from utils import encrypt_file, decrypt_file, data_to_file
from utils import generate_storage_filename, bytes_to_readable, calculate_sha256

anonymous_bp = Blueprint('anonymous', __name__, url_prefix='/anonymous')

EXPIRATION_DELTA = SERVER_CONFIG.max_expiration
ANONYMOUS_UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "anonymous_stored_files")

if not os.path.exists(ANONYMOUS_UPLOAD_FOLDER):
    os.makedirs(ANONYMOUS_UPLOAD_FOLDER)


@anonymous_bp.route('/upload_file', methods=['POST'])
def upload_file():
    if 'file' not in request.files or not request.form.get("encrypted_key"):
        return jsonify({"message": "File and encrypted key are required"}), 400
    file = request.files['file']
    filename = file.filename
    storage_filename = generate_storage_filename(filename, f"anonymous{datetime.datetime.now().timestamp()}")
    sha256_checksum = request.form.get("sha256_checksum")
    if not sha256_checksum:
        return jsonify({"message": "SHA256 checksum is required"}), 400
    file_data = file.read()
    if 0 < SERVER_CONFIG.max_file_size < len(file_data):
        return jsonify({
            "message": f"File size {bytes_to_readable(len(file_data))} exceeds"
                       f" the maximum limit of {bytes_to_readable(SERVER_CONFIG.max_file_size)}"}
        ), 400
    actual_checksum = calculate_sha256(file_data)
    if sha256_checksum != actual_checksum:
        return jsonify({"message": "Checksum verification failed"}), 400
    current_timestamp = datetime.datetime.now(datetime.timezone.utc)
    expiration_timestamp = current_timestamp + datetime.timedelta(seconds=EXPIRATION_DELTA)
    file_path = os.path.join(ANONYMOUS_UPLOAD_FOLDER, storage_filename)
    file_data = encrypt_file(file_data)
    with open(file_path, "wb") as f:
        f.write(file_data)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO file_anonymous (filename, storage_path, encrypted_key, upload_timestamp, expiration_timestamp)
        VALUES (%s, %s, %s, %s, %s) RETURNING file_id; 
        """,
        (filename, file_path, request.form.get("encrypted_key"), current_timestamp, expiration_timestamp)
    )
    conn.commit()
    return jsonify({"message": "File uploaded successfully"}), 200


@anonymous_bp.route('/list_files', methods=['GET'])
def list_files():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT file_id, filename, expiration_timestamp
        FROM file_anonymous
        WHERE expiration_timestamp > %s
        ORDER BY upload_timestamp DESC;
        """,
        (datetime.datetime.now(datetime.timezone.utc),)
    )
    files = cursor.fetchall()
    file_list = [
        {
            "file_id": f"a_{file[0]}",
            "filename": file[1],
            "expiration_timestamp": file[2]
        }
        for file in files
    ]
    return jsonify({"files": file_list}), 200


@anonymous_bp.route('/file_info/<string:file_id>', methods=['GET'])
def file_info(file_id):
    if not file_id.startswith("a_") or not file_id[2:].isdigit():
        return jsonify({"message": "Invalid file ID"}), 400
    file_id = int(file_id[2:])
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT filename, encrypted_key, upload_timestamp, expiration_timestamp
        FROM file_anonymous
        WHERE file_id = %s AND expiration_timestamp > %s;
        """,
        (file_id, datetime.datetime.now(datetime.timezone.utc))
    )
    result = cursor.fetchone()
    if not result:
        return jsonify({"message": "File not found or expired"}), 404
    filename, encrypted_key, upload_timestamp, expiration_timestamp = result
    info = {
        "filename": filename,
        "encrypted_key": encrypted_key,
        "upload_timestamp": upload_timestamp,
        "expiration_timestamp": expiration_timestamp
    }
    return jsonify({"file_info": info}), 200


@anonymous_bp.route('/download_file/<string:file_id>', methods=['GET'])
def download_file(file_id):
    if not file_id.startswith("a_") or not file_id[2:].isdigit():
        return jsonify({"message": "Invalid file ID"}), 400
    file_id = int(file_id[2:])
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT filename, storage_path, encrypted_key, expiration_timestamp
        FROM file_anonymous
        WHERE file_id = %s AND expiration_timestamp > %s;
        """,
        (file_id, datetime.datetime.now(datetime.timezone.utc))
    )
    result = cursor.fetchone()
    if not result:
        return jsonify({"message": "File not found or expired"}), 404

    filename, storage_path, encrypted_key, expiration_timestamp = result

    if not os.path.exists(storage_path):
        return jsonify({"message": "File not found"}), 404

    with open(storage_path, "rb") as f:
        file_data = f.read()
    file = data_to_file(decrypt_file(file_data))

    return send_file(file, as_attachment=True, download_name=filename)
