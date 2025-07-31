import os
import shutil
import stat
import psycopg2
from psycopg2 import OperationalError
from config import DB_CONFIG, TARGET_USER, PRIVILEGES

def prepare_client_key(src_path, dst_path):
    try:
        shutil.copy(src_path, dst_path)
        os.chmod(dst_path, stat.S_IRUSR | stat.S_IWUSR)  # chmod 600
#        print(f"✅ Copied client key to {dst_path} with secure permissions.")
        return dst_path
    except Exception as e:
        print(f"❌ Failed to prepare client key: {e}")
        return src_path  # fallback (but connection will likely fail)

def check_db_connection():
    try:
        print("Connecting to the database...")
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("SELECT current_database();")
        db = cur.fetchone()[0]
        cur.execute("SELECT current_user;")
        user = cur.fetchone()[0]
        print(f"✅ Successfully connected to database: {db} as user: {user}")
        cur.close()
        conn.close()
        return True
    except OperationalError as e:
        print(f"❌ Connection failed: {e}")
        return False

def get_tables(schema='public'):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        query = """
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = %s AND table_type = 'BASE TABLE';
        """
        cur.execute(query, (schema,))
        tables = [row[0] for row in cur.fetchall()]
        cur.close()
        conn.close()
        return tables
    except Exception as e:
        print(f"❌ Failed to fetch tables: {e}")
        return []

def fetch_user_privileges(username=TARGET_USER, schema='public'):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        query = """
        SELECT table_name, privilege_type
        FROM information_schema.role_table_grants
        WHERE grantee = %s AND table_schema = %s
        ORDER BY table_name;
        """
        cur.execute(query, (username, schema))
        rows = cur.fetchall()

        priv_map = {}
        for table_name, privilege in rows:
            priv_map.setdefault(table_name, set()).add(privilege)

        cur.close()
        conn.close()

        return priv_map
    except Exception as e:
        print(f"❌ Failed to fetch privileges: {e}")
        return {}

def print_summarized_privileges(username=TARGET_USER, priv_map=None):
    if not priv_map:
        print(f"\nNo privileges found for user '{username}'.")
        return

    tables_list = sorted(priv_map.keys())
    tables_str = "', '".join(tables_list)

    all_privs = set()
    for privs in priv_map.values():
        all_privs.update(privs)

    priv_str = ", ".join(sorted(all_privs))
    print(f"\nCurrent privileges for user '{username}' for tables '{tables_str}' is : {priv_str}")

def update_user_privileges(tables, schema='public', username=TARGET_USER, privileges_list=PRIVILEGES):
    try:
        print(f"\nUpdating privileges on tables '{', '.join(tables)}' for user '{username}'...")

        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        for table_name in tables:
            revoke_query = f"REVOKE ALL PRIVILEGES ON TABLE {schema}.{table_name} FROM {username};"
            cur.execute(revoke_query)

            if privileges_list:
                privs = ", ".join(privileges_list)
                grant_query = f"GRANT {privs} ON TABLE {schema}.{table_name} TO {username};"
                cur.execute(grant_query)

        conn.commit()
        cur.close()
        conn.close()
        return True

    except OperationalError as e:
        print(f"❌ Failed to update privileges: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    # Fix SSL private key permissions for libpq
    client_key_src = '/secrets/client-key/client-key.pem'
    client_key_dst = '/tmp/client-key.pem'
    DB_CONFIG['sslkey'] = prepare_client_key(client_key_src, client_key_dst)

    schema_name = 'public'

    if check_db_connection():
        tables = get_tables(schema_name)
        if not tables:
            print(f"No tables found in schema '{schema_name}'. Exiting.")
            exit(1)

        priv_map = fetch_user_privileges(TARGET_USER, schema_name)
        print_summarized_privileges(TARGET_USER, priv_map)

        success = update_user_privileges(tables, schema_name, TARGET_USER, PRIVILEGES)
        if success:
            print(f"✅ Updated privileges to [{', '.join(PRIVILEGES)}] for user '{TARGET_USER}'")
        else:
            print(f"❌ Failed to update privileges for user '{TARGET_USER}'")

        exit(0)
    else:
        exit(1)
