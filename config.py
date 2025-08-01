def read_secret(path):
    try:
        with open(path) as f:https://github.com/Ajithkumar8006/sql-db-user-update/blob/main/config.py
            return f.read().strip()
    except Exception as e:
        raise RuntimeError(f"❌ Failed to read secret from {path}: {e}")

DB_CONFIG = {
    'host': '10.15.69.9',
    'port': 5432,
    'dbname': 'testdb',
    'user': 'pgadmin',
    'password': read_secret('/secrets/admin-password/pg-admin-user-password'),
    'sslmode': 'verify-ca',
    'sslrootcert': '/secrets/server-ca/server-ca.pem',
    'sslcert': '/secrets/client-cert/client-cert.pem',
    # 'sslkey': '/secrets/client-key/client-key.pem'
}

TARGET_USER = 'appuser'
PRIVILEGES = ['INSERT','SELECT','UPDATE']
