# Secure File Sharing System

## Overview

This project is a secure file-sharing and storage system designed for controlled, encrypted file access and sharing
between authenticated users. The system uses a Flask-based server and a command-line client. Files are encrypted on the
client-side before upload, and access control is maintained by securely sharing decryption keys with authorized users.

### Key Features

1. **Challenge-Response Authentication**:
    - Users authenticate with a challenge-response mechanism that uses RSA public/private keys.
    - The server issues a session token upon successful authentication, allowing users to perform further actions until
      the session expires.

2. **Session Management**:
    - Sessions are tracked in an in-memory store on the server with configurable timeouts.
    - A periodic heartbeat from the client keeps the session active, and users are logged out if the heartbeat stops or
      the session times out.

3. **File Encryption and Storage**:
    - Files are encrypted on the client-side with AES using a randomly generated symmetric key.
    - This symmetric key is encrypted with the user’s RSA public key, ensuring only the user can decrypt and access the
      original file.
    - Encrypted files are uploaded to the server with a unique, hashed filename for storage.

4. **Access Control and File Sharing**:
    - Users can share files with other authorized users by re-encrypting the file’s decryption key with the recipient's
      public key.
    - Shared decryption keys are stored in a secure `shared_files` table, allowing authorized users to access shared
      files.

5. **User Interface and Client Commands**:
    - The client is command-line based, providing options for actions like `upload`, `download`, `share`, `list`, and
      `exit`.
    - Each action involves encrypted communication with the server, ensuring all transmitted data is protected.

### Project Structure

- [**Server Code**](./server/main.py): Manages user sessions, file uploads/downloads, and file sharing. Uses PostgreSQL
  to store user credentials, file metadata, and access control information.
- [**Client Code**](./client/main.py): A command-line tool for interacting with the server, handling authentication,
  file encryption, and operations like upload, download, and share.
- [**Database Schema**](./server/run_once/setup_db.sql):
    - `user_credentials`: Stores user information, RSA public keys, and other authentication data.
    - `files`: Holds metadata for each uploaded file, including storage path, encrypted keys, and access limits.
    - `shared_files`: Manages access control for shared files by storing encrypted decryption keys for each authorized
      user.

### Current Implementation

- **Authentication and Session Management**: Implemented with challenge-response and session tokens.
- **File Upload and Download**: Supported with AES-GCM encryption on the client-side and secure key handling.
- **Access Control**: Implemented through RSA encryption for sharing decryption keys.
- **User Command Line**: Client application provides a command-line interface for all main actions, with session-based
  authorization.
- **Database**: PostgreSQL database with tables for user credentials, file metadata, and shared file access.

### To Be Done

- **Audit and Log Access Attempts**:
    - Track and log access attempts for audit and security analysis.

- **Enhance Key Management**:
    - Implement automated key rotation and better handling of key expiration/revocation.

- **Improved Error Handling**:
    - Refine error messages and handling for various edge cases and network issues.

- **Searchable Multi-Key Symmetric Encryption**:
    - Implement a searchable symmetric encryption scheme for user to search for files without revealing the contents.

- **Deduplication of Encrypted Files**:
    - Implement a mechanism to deduplicate files on the server side to save storage space.

### Authors :
-**1)Mayank Garg**
-**2)Guangyan An**
-**3)Yash Kishore** 
  
