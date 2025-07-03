# Challenge-Response User Authentication System Setup

## Overview

This setup is for a "run once" server configuration of a challenge-response user authentication system using RSA
public/private keys. The process includes:

1. Configuring a PostgreSQL database to store user credentials.
2. Populating the database with a fixed set of example users and verifying the challenge-response mechanism.

The setup assumes the presence of an [`example_users/`](../../example_users) folder containing:

- [`user_data.json`](../../example_users/user_data.json): A JSON file listing usernames and the file paths to
  corresponding public and private keys.
- [`keys/`](../../example_users/keys): A directory with PEM-formatted RSA public and private key pairs for each user.

## Prerequisites

- **PostgreSQL** installed and running.
- **Python 3** installed.
- **Python packages**: Install `psycopg2` and `cryptography` with:
  ```bash
  pip install psycopg2 cryptography
  ```

## Database Configuration

Execute the [setup_db.sql](setup_db.sql) script to create the database schema and tables.

```bash
psql -U postgres -f setup_db.sql
# For windows users you can find the psql executable in the bin folder of the PostgreSQL installation directory in 'bin' folder
```

## Populate the Database and Test Authentication

Run the [populate_and_authenticate.py](./populate_and_authenticate.py) script to populate the database with the example
users and test the challenge-response mechanism.

```bash
python populate_and_authenticate.py
```