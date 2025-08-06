def read_secret(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception as e:
        raise RuntimeError(f"❌ Failed to read secret from {path}: {e}")

DB_CONFIG = {
    'host': '10.15.69.15',
    'port': 5432,
    'dbname': 'communication_csv_db',
    'user': 'communication_csv_db',
    'password': read_secret('/secrets/communication_csv_db/communication_csv_db'),
    'sslmode': 'verify-ca',
    'sslrootcert': '/secrets/server-ca/server-ca.pem',
    'sslcert': '/secrets/client-cert/client-cert.pem',
    # 'sslkey': '/secrets/client-key/client-key.pem'
}

TARGET_USER = 'appuser'
#PRIVILEGES = ['INSERT','SELECT','UPDATE']
PRIVILEGES = ['INSERT']
