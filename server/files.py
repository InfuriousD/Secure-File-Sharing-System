import datetime
import os

from flask import Blueprint, request, jsonify, send_file

from config import SERVER_CONFIG
from db import get_db_connection
from utils import bytes_to_readable
from utils import encrypt_file, decrypt_file, data_to_file
from utils import get_user_id_by_username, get_user_encryption_key_by_username
from utils import validate_session, generate_storage_filename, calculate_sha256

files_bp = Blueprint("files", __name__)

MAX_EXPIRATION_DELTA = SERVER_CONFIG.max_expiration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stored_files")

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


@files_bp.route('/upload_file', methods=['POST'])
@validate_session
def upload_file():
    if 'file' not in request.files or not request.form.get("encrypted_key"):
        return jsonify({"message": "File and encrypted key are required"}), 400
    file = request.files['file']
    filename = file.filename
    storage_filename = generate_storage_filename(filename, request.user_id)
    encrypted_key = request.form.get("encrypted_key")
    download_limit = int(request.form.get("download_limit"))  # 0 means unlimited
    expiration_delta = int(request.form.get("expiration_delta"))  # seconds
    sha256_checksum = request.form.get("sha256_checksum")
    if any(_x is None for _x in (storage_filename, encrypted_key, download_limit, expiration_delta, sha256_checksum)):
        return jsonify({"message": "Encrypted key, download limit, expiration delta, and checksum are required"}), 400
    file_data = file.read()
    if 0 < SERVER_CONFIG.max_file_size < len(file_data):
        return jsonify({
            "message": f"File size {bytes_to_readable(len(file_data))} exceeds"
                       f" the maximum limit of {bytes_to_readable(SERVER_CONFIG.max_file_size)}"}
        ), 400
    actual_checksum = calculate_sha256(file_data)
    if sha256_checksum != actual_checksum:
        return jsonify({"message": "Checksum verification failed"}), 400
    if expiration_delta < 0 or expiration_delta > MAX_EXPIRATION_DELTA:
        return jsonify({"message": "Invalid expiration delta"}), 400

    current_timestamp = datetime.datetime.now(datetime.timezone.utc)
    expiration_timestamp = current_timestamp + datetime.timedelta(seconds=expiration_delta)

    # Save file to server
    file_path = os.path.join(UPLOAD_FOLDER, storage_filename)
    # file.save(file_path)
    file_data = encrypt_file(file_data)
    with open(file_path, "wb") as f:
        f.write(file_data)

    # Insert file metadata into the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO files (filename, storage_path, owner_id, encrypted_key, download_limit, upload_timestamp, expiration_timestamp)
        VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING file_id;
        """,
        (filename, file_path, request.user_id, encrypted_key, download_limit, current_timestamp, expiration_timestamp)
    )
    conn.commit()

    return jsonify({"message": "File uploaded successfully"}), 200


@files_bp.route('/list_files', methods=['GET'])
@validate_session
def list_files():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT f.file_id, f.filename, f.owner_id, f.download_count, f.download_limit, f.expiration_timestamp
        FROM files f
        LEFT JOIN shared_files s ON f.file_id = s.file_id
        WHERE f.owner_id = %s OR s.user_id = %s
        GROUP BY f.file_id;
    """, (request.user_id, request.user_id))

    files = cursor.fetchall()

    file_list = [
        {
            "file_id": file[0],
            "filename": file[1],
            "owner_id": file[2],
            "download_count": file[3],
            "download_limit": file[4],
            "expiration_timestamp": file[5]
        }
        for file in files
    ]
    return jsonify({"files": file_list}), 200


# Endpoint to get file info
@files_bp.route('/file_info/<int:file_id>', methods=['GET'])
@validate_session
def get_file_info(file_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT f.filename, 
               f.owner_id, 
               f.download_count, 
               f.download_limit, 
               f.upload_timestamp,
               f.expiration_timestamp,
               CASE 
                   WHEN s.user_id IS NOT NULL THEN s.encrypted_key 
                   ELSE f.encrypted_key 
               END AS encrypted_key
        FROM files f
        LEFT JOIN shared_files s ON f.file_id = s.file_id AND s.user_id = %s
        WHERE f.file_id = %s AND (f.owner_id = %s OR s.user_id = %s);

    """, (request.user_id, file_id, request.user_id, request.user_id))
    file = cursor.fetchone()
    if not file:
        return jsonify({"message": "File not found"}), 404

    file_info = {
        "filename": file[0],
        "owner_id": file[1],
        "download_count": file[2],
        "download_limit": file[3],
        "upload_timestamp": file[4],
        "expiration_timestamp": file[5],
        "encrypted_key": file[6]
    }
    return jsonify({"file_info": file_info}), 200


# Endpoint to get user encryption key
@files_bp.route('/encryption_key/<string:username>', methods=['GET'])
@validate_session
def get_encryption_key(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    encryption_key = get_user_encryption_key_by_username(username, cursor)
    if not encryption_key:
        return jsonify({"message": "User not found"}), 404

    return jsonify({"encryption_key": encryption_key}), 200


# Endpoint to share a file with another user
@files_bp.route('/share_file', methods=['POST'])
@validate_session
def share_file():
    data = request.json
    file_id = data.get("file_id")
    share_with_username = data.get("share_with_username")
    target_decryption_key = data.get("target_decryption_key")

    if not file_id or not share_with_username or not target_decryption_key:
        return jsonify({"message": "File ID, username, and decryption key are required"}), 400

    # Check if the file exists and is owned by the current user
    conn = get_db_connection()
    cursor = conn.cursor()
    # cursor.execute("SELECT owner_id FROM files WHERE file_id = %s", (file_id,))
    cursor.execute(
        """
        SELECT owner_id,
               download_count,
               download_limit,
               expiration_timestamp
        FROM files WHERE file_id = %s
        """, (file_id,))
    result = cursor.fetchone()
    if not result:
        return jsonify({"message": "File not found"}), 404
    owner_id, download_count, download_limit, expiration_timestamp = result
    if owner_id != request.user_id:
        return jsonify({"message": "You do not have permission to share this file"}), 403
    if datetime.datetime.now(datetime.timezone.utc) > expiration_timestamp:
        return jsonify({"message": "File is no longer available"}), 403
    if 0 < download_limit <= download_count:
        return jsonify({"message": "Download limit exceeded"}), 403

    # Check if the target user exists
    target_user_id = get_user_id_by_username(share_with_username, cursor)
    if not target_user_id:
        return jsonify({"message": "Target user not found"}), 404

    # Insert the shared file record
    cursor.execute(
        "INSERT INTO shared_files (file_id, user_id, encrypted_key) VALUES (%s, %s, %s)",
        (file_id, target_user_id, target_decryption_key)
    )
    conn.commit()

    return jsonify({"message": "File shared successfully"}), 200


# Endpoint to download a file
@files_bp.route('/download_file/<int:file_id>', methods=['GET'])
@validate_session
def download_file(file_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT filename, storage_path, owner_id, download_count, download_limit, expiration_timestamp
        FROM files
        WHERE file_id = %s
        """,
        (file_id,)
    )
    result = cursor.fetchone()
    if not result:
        return jsonify({"message": "File not found"}), 404

    filename, storage_path, owner_id, download_count, download_limit, expiration_timestamp = result

    if expiration_timestamp < datetime.datetime.now(datetime.timezone.utc):
        return jsonify({"message": "File is no longer available)"}), 403
    if request.user_id != owner_id:
        # Find if the file is shared with the user
        cursor.execute(
            "SELECT encrypted_key FROM shared_files WHERE file_id = %s AND user_id = %s",
            (file_id, request.user_id)
        )
        shared_encrypted_key = cursor.fetchone()
        if not shared_encrypted_key:
            return jsonify({"message": "You do not have permission to download this file"}), 403
    if 0 < download_limit <= download_count:
        return jsonify({"message": "Download limit exceeded"}), 403

    cursor.execute("UPDATE files SET download_count = download_count + 1 WHERE file_id = %s", (file_id,))
    conn.commit()

    if not os.path.exists(storage_path):
        return jsonify({"message": "File not found on the server"}), 404

    with open(storage_path, "rb") as f:
        file_data = f.read()
    file = data_to_file(decrypt_file(file_data))

    return send_file(file, as_attachment=True, download_name=filename)


@files_bp.route('/delete_file/<int:file_id>', methods=['DELETE'])
@validate_session
def delete_file(file_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT owner_id, storage_path FROM files WHERE file_id = %s", (file_id,))
    result = cursor.fetchone()
    if not result:
        return jsonify({"message": "File not found"}), 404

    owner_id, storage_path = result
    if owner_id != request.user_id:
        return jsonify({"message": "You do not have permission to delete this file"}), 403

    # Delete shared file records
    cursor.execute("DELETE FROM shared_files WHERE file_id = %s", (file_id,))
    cursor.execute("DELETE FROM files WHERE file_id = %s", (file_id,))
    conn.commit()

    if os.path.exists(storage_path):
        os.remove(storage_path)

    return jsonify({"message": "File deleted successfully"}), 200
