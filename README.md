# sql-db-user-update
sql db user rights update 
-----
terraform apply -var-file="vars/dev.tfvars"
------------------------------------- 
 cat main.tf
-------------------------------------
provider "google" {
  project = var.project_id
  region  = var.region
}

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

# Generate passwords
resource "random_password" "admin_password" {
  length           = 16
  special          = true
  override_special = "!@#$%^&*"
}

resource "random_password" "app_user_password" {
  length           = 16
  special          = true
  override_special = "!@#$%^&*"
}

# Create PostgreSQL instance
resource "google_sql_database_instance" "postgres_instance" {
  name             = var.db_instance_name
  region           = var.region
  database_version = "POSTGRES_14"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true
      require_ssl = true
      ssl_mode    = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"

      authorized_networks {
        name  = "allow-all"
        value = "0.0.0.0/0"
      }
    }
  }

  deletion_protection = false 
}

# Create test database
resource "google_sql_database" "testdb" {
  name     = var.db_name
  instance = google_sql_database_instance.postgres_instance.name
}

# Create admin user
resource "google_sql_user" "admin_user" {
  name     = var.admin_user
  instance = google_sql_database_instance.postgres_instance.name
  password = random_password.admin_password.result
}

# Create app user
resource "google_sql_user" "app_user" {
  name     = var.app_user
  instance = google_sql_database_instance.postgres_instance.name
  password = random_password.app_user_password.result
}

# Store admin password in Secret Manager
resource "google_secret_manager_secret" "admin_password" {
  secret_id = "pg-admin-user-password"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "admin_password_version" {
  secret      = google_secret_manager_secret.admin_password.id
  secret_data = random_password.admin_password.result
}

# Store app user password in Secret Manager
resource "google_secret_manager_secret" "app_user_password" {
  secret_id = "pg-app-user-password"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "app_user_password_version" {
  secret      = google_secret_manager_secret.app_user_password.id
  secret_data = random_password.app_user_password.result
}

# ---------------------
# Generate Client SSL Cert for Secure Connection
# ---------------------
resource "google_sql_ssl_cert" "client_ssl_cert" {
  common_name = "pg-client"
  instance    = google_sql_database_instance.postgres_instance.name
  project     = var.project_id
}

# ---------------------
# Store Client SSL Certs in Secret Manager
# ---------------------
resource "google_secret_manager_secret" "client_cert" {
  secret_id = "pg-client-cert"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "client_cert_version" {
  secret      = google_secret_manager_secret.client_cert.id
  secret_data = google_sql_ssl_cert.client_ssl_cert.cert
}

resource "google_secret_manager_secret" "client_private_key" {
  secret_id = "pg-client-private-key"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "client_private_key_version" {
  secret      = google_secret_manager_secret.client_private_key.id
  secret_data = google_sql_ssl_cert.client_ssl_cert.private_key
}

resource "google_secret_manager_secret" "server_ca_cert" {
  secret_id = "pg-server-ca-cert"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "server_ca_cert_version" {
  secret      = google_secret_manager_secret.server_ca_cert.id
  secret_data = google_sql_ssl_cert.client_ssl_cert.server_ca_cert
}

resource "google_project_iam_member" "secret_manager_access" {
  project = var.project_id   # or "apigee-test-0002-demo"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:741169614600-compute@developer.gserviceaccount.com"
}

resource "google_cloud_run_v2_job" "update_user_privileges" {
  name     = "update-user-privileges-job"
  location = var.region

  template {
    template {
      containers {
        image = "gcr.io/${var.project_id}/update-user-privileges"

        volume_mounts {
          name       = "client-cert"
          mount_path = "/secrets/client-cert"
        }

        volume_mounts {
          name       = "client-key"
          mount_path = "/secrets/client-key"
        }

        volume_mounts {
          name       = "server-ca"
          mount_path = "/secrets/server-ca"
        }

        volume_mounts {
          name       = "admin-password"
          mount_path = "/secrets/admin-password"
        }

        env {
          name  = "PGSSLCERT"
          value = "/secrets/client-cert/client-cert.pem"
        }

        env {
          name  = "PGSSLKEY"
          value = "/secrets/client-key/client-key.pem"
        }

        env {
          name  = "PGSSLROOTCERT"
          value = "/secrets/server-ca/server-ca.pem"
        }
      }

      volumes {
        name = "client-cert"
        secret {
          secret = "pg-client-cert"
          items {
            path    = "client-cert.pem"
            version = "latest"
          }
        }
      }

      volumes {
        name = "client-key"
        secret {
          secret = "pg-client-private-key"
          items {
            path    = "client-key.pem"
            version = "latest"
          }
        }
      }

      volumes {
        name = "server-ca"
        secret {
          secret = "pg-server-ca-cert"
          items {
            path    = "server-ca.pem"
            version = "latest"
          }
        }
      }

      volumes {
        name = "admin-password"
        secret {
          secret = "pg-admin-user-password"
          items {
            path    = "pg-admin-user-password"
            version = "latest"
          }
        }
      }

      service_account = "741169614600-compute@developer.gserviceaccount.com"
    }
  }
}

-------------------------------------

cat main.tf  - private_network 
-------------------------------------                                       
provider "google" {
  project = var.project_id
  region  = var.region
}

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

# Generate passwords
resource "random_password" "admin_password" {
  length           = 16
  special          = true
  override_special = "!@#$%^&*"
}

resource "random_password" "app_user_password" {
  length           = 16
  special          = true
  override_special = "!@#$%^&*"
}

# Create PostgreSQL instance with PRIVATE IP
resource "google_sql_database_instance" "postgres_instance" {
  name             = var.db_instance_name
  region           = var.region
  database_version = "POSTGRES_14"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/${var.project_id}/global/networks/default"
      require_ssl     = true
      ssl_mode        = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
    }
  }

  deletion_protection = false
}

# Create test database
resource "google_sql_database" "testdb" {
  name     = var.db_name
  instance = google_sql_database_instance.postgres_instance.name
}

# Create admin user
resource "google_sql_user" "admin_user" {
  name     = var.admin_user
  instance = google_sql_database_instance.postgres_instance.name
  password = random_password.admin_password.result
}

# Create app user
resource "google_sql_user" "app_user" {
  name     = var.app_user
  instance = google_sql_database_instance.postgres_instance.name
  password = random_password.app_user_password.result
}

# Store admin password in Secret Manager
resource "google_secret_manager_secret" "admin_password" {
  secret_id = "pg-admin-user-password"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "admin_password_version" {
  secret      = google_secret_manager_secret.admin_password.id
  secret_data = random_password.admin_password.result
}

# Store app user password in Secret Manager
resource "google_secret_manager_secret" "app_user_password" {
  secret_id = "pg-app-user-password"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "app_user_password_version" {
  secret      = google_secret_manager_secret.app_user_password.id
  secret_data = random_password.app_user_password.result
}

# Generate Client SSL Cert for Secure Connection
resource "google_sql_ssl_cert" "client_ssl_cert" {
  common_name = "pg-client"
  instance    = google_sql_database_instance.postgres_instance.name
  project     = var.project_id
}

# Store Client SSL Certs in Secret Manager
resource "google_secret_manager_secret" "client_cert" {
  secret_id = "pg-client-cert"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "client_cert_version" {
  secret      = google_secret_manager_secret.client_cert.id
  secret_data = google_sql_ssl_cert.client_ssl_cert.cert
}

resource "google_secret_manager_secret" "client_private_key" {
  secret_id = "pg-client-private-key"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "client_private_key_version" {
  secret      = google_secret_manager_secret.client_private_key.id
  secret_data = google_sql_ssl_cert.client_ssl_cert.private_key
}

resource "google_secret_manager_secret" "server_ca_cert" {
  secret_id = "pg-server-ca-cert"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "server_ca_cert_version" {
  secret      = google_secret_manager_secret.server_ca_cert.id
  secret_data = google_sql_ssl_cert.client_ssl_cert.server_ca_cert
}

# VPC Access for Cloud Run
resource "google_vpc_access_connector" "vpc_connector" {
  name          = "cloud-run-vpc-connector"
  region        = var.region
  network       = "default"
  ip_cidr_range = "10.8.0.0/28"
}

# IAM: Access to secrets
resource "google_project_iam_member" "secret_manager_access" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:741169614600-compute@developer.gserviceaccount.com"
}

# IAM: Access to VPC connector
resource "google_project_iam_member" "vpcaccess_user" {
  project = var.project_id
  role    = "roles/vpcaccess.user"
  member  = "serviceAccount:741169614600-compute@developer.gserviceaccount.com"
}

# Cloud Run job using private IP via VPC connector
resource "google_cloud_run_v2_job" "update_user_privileges" {
  name     = "update-user-privileges-job"
  location = var.region

  template {
    template {
      containers {
        image = "gcr.io/${var.project_id}/update-user-privileges"

        volume_mounts {
          name       = "client-cert"
          mount_path = "/secrets/client-cert"
        }

        volume_mounts {
          name       = "client-key"
          mount_path = "/secrets/client-key"
        }

        volume_mounts {
          name       = "server-ca"
          mount_path = "/secrets/server-ca"
        }

        volume_mounts {
          name       = "admin-password"
          mount_path = "/secrets/admin-password"
        }

        env {
          name  = "PGSSLCERT"
          value = "/secrets/client-cert/client-cert.pem"
        }

        env {
          name  = "PGSSLKEY"
          value = "/secrets/client-key/client-key.pem"
        }

        env {
          name  = "PGSSLROOTCERT"
          value = "/secrets/server-ca/server-ca.pem"
        }

        env {
          name  = "DB_HOST"
          value = google_sql_database_instance.postgres_instance.private_ip_address
        }
      }

      volumes {
        name = "client-cert"
        secret {
          secret = "pg-client-cert"
          items {
            path    = "client-cert.pem"
            version = "latest"
          }
        }
      }

      volumes {
        name = "client-key"
        secret {
          secret = "pg-client-private-key"
          items {
            path    = "client-key.pem"
            version = "latest"
          }
        }
      }

      volumes {
        name = "server-ca"
        secret {
          secret = "pg-server-ca-cert"
          items {
            path    = "server-ca.pem"
            version = "latest"
          }
        }
      }

      volumes {
        name = "admin-password"
        secret {
          secret = "pg-admin-user-password"
          items {
            path    = "pg-admin-user-password"
            version = "latest"
          }
        }
      }

      vpc_access {
        connector = google_vpc_access_connector.vpc_connector.id
        egress    = "ALL_TRAFFIC"
      }

      service_account = "741169614600-compute@developer.gserviceaccount.com"
    }
  }
}


-------
cat variables.tf 
-------------------------------------
variable "project_id" {
  description = "GCP Project ID"
  type        = string
  default     = "apigee-test-0002-demo"
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "db_instance_name" {
  description = "Name of the PostgreSQL instance"
  type        = string
  default     = "pg-instance"
}

variable "db_name" {
  description = "Name of the test database"
  type        = string
  default     = "testdb"
}

# Admin user for full access
variable "admin_user" {
  description = "Admin database user with full privileges"
  type        = string
  default     = "pgadmin"
}

# Application user for limited access
variable "app_user" {
  description = "App user with limited privileges"
  type        = string
  default     = "appuser"
}

variable "postgres_instance_public_ip" {
  description = "Public IP of the PostgreSQL instance"
  type        = string
}
-------------------------------------
cat vars/dev.tfvars 
-------------------------------------
project_id       = "apigee-test-0002-demo"
region           = "us-central1"
db_instance_name = "pg-instance"
db_name          = "testdb"

# New user variables
admin_user       = "pgadmin"
app_user         = "appuser"

----------------------------------
cat main.py
----------------------------------
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
----------------------------------
cat config.py 
----------------------------------                                    
def read_secret(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception as e:
        raise RuntimeError(f"❌ Failed to read secret from {path}: {e}")

DB_CONFIG = {
    'host': '34.45.35.7',
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
PRIVILEGES = ['SELECT','UPDATE']

-----------------
cat Dockerfile
-----------------

# Use slim Python base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files
COPY . .

# Set environment variable for SSL
ENV PGSSLMODE=verify-ca

# Fix permissions on private key before running main.py (fallback)
CMD ["python", "main.py"]

------------------
gcloud builds submit . \                              
  --tag gcr.io/apigee-test-0002-demo/sql-update-user-privileges
---------
gcloud run jobs create sql-update-user-privileges-job \
  --image gcr.io/apigee-test-0002-demo/sql-update-user-privileges \
  --region us-central1

--------
gcloud run jobs execute sql-update-user-privileges-job \
  --region us-central1

------------
gcloud run jobs execute sql-update-user-privileges-job
