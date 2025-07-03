-- Create the cnt5410project database
CREATE DATABASE cnt5410project;
\c cnt5410project;

-- Create the manager role with login and password
CREATE ROLE cnt5410_mgr LOGIN PASSWORD 'strong_password';

-- Create the user_credentials table
CREATE TABLE user_credentials
(
    user_id           SERIAL PRIMARY KEY,
    username          VARCHAR(50) UNIQUE    NOT NULL,
    verifier          TEXT,
    salt              TEXT,
    public_key        TEXT,
    encryption_key    TEXT                  NOT NULL,
    password_disabled BOOLEAN DEFAULT FALSE NOT NULL,
    last_challenge    TEXT,
    CONSTRAINT at_least_one_not_null CHECK (
        ((verifier IS NOT NULL AND salt IS NOT NULL) OR public_key IS NOT NULL)
            AND (NOT password_disabled OR public_key IS NOT NULL)
        )
);


-- Grant necessary permissions to the manager role
ALTER TABLE user_credentials
    OWNER TO cnt5410_mgr;
GRANT SELECT, INSERT, UPDATE ON user_credentials TO cnt5410_mgr;

-- Create the files table to store file metadata and access control information
CREATE TABLE files
(
    file_id              SERIAL PRIMARY KEY,
    filename             VARCHAR(255)             NOT NULL,
    storage_path         VARCHAR(255)             NOT NULL,
    owner_id             INT                      NOT NULL REFERENCES user_credentials (user_id),
    encrypted_key        TEXT                     NOT NULL, -- The encrypted decryption key for the file
    download_limit       INT DEFAULT 0            NOT NULL, -- Max number of downloads allowed (0 means unlimited)
    download_count       INT DEFAULT 0            NOT NULL, -- Number of times the file has been downloaded
    upload_timestamp     TIMESTAMP WITH TIME ZONE NOT NULL,
    expiration_timestamp TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Create the file_anonymous table to store anonymous upload information
CREATE TABLE file_anonymous
(
    file_id              SERIAL PRIMARY KEY,
    filename             VARCHAR(255)             NOT NULL,
    storage_path         VARCHAR(255)             NOT NULL,
    encrypted_key        TEXT                     NOT NULL, -- The encrypted decryption key for the file
    upload_timestamp     TIMESTAMP WITH TIME ZONE NOT NULL,
    expiration_timestamp TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Create the shared_files table to manage shared access and store encrypted decryption keys
CREATE TABLE shared_files
(
    shared_id     SERIAL PRIMARY KEY,
    file_id       INT  NOT NULL REFERENCES files (file_id),
    user_id       INT  NOT NULL REFERENCES user_credentials (user_id), -- ID of the user the file is shared with
    encrypted_key TEXT NOT NULL                                        -- The decryption key encrypted with the shared user's public key
);

-- Grant necessary permissions to the manager role
ALTER TABLE files
    OWNER TO cnt5410_mgr;
ALTER TABLE file_anonymous
    OWNER TO cnt5410_mgr;
ALTER TABLE shared_files
    OWNER TO cnt5410_mgr;
GRANT SELECT, INSERT, UPDATE, DELETE ON files TO cnt5410_mgr;
GRANT SELECT, INSERT, UPDATE, DELETE ON file_anonymous TO cnt5410_mgr;
GRANT SELECT, INSERT, UPDATE, DELETE ON shared_files TO cnt5410_mgr;
