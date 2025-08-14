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
resource "google_cloud_run_v2_job" "sql-update_user_privileges" {
  name     = "sql-update-user-privileges-job"
  location = var.region

  template {
    template {
      containers {
        image = "gcr.io/${var.project_id}/sql-update-user-privileges"

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

# Cloud Run job using private IP via VPC connector
resource "google_cloud_run_v2_job" "sql-db-table-create" {
  name     = "sql-db-table-create"
  location = var.region

  template {
    template {
      containers {
        image = "gcr.io/${var.project_id}/sql-db-table-create"

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
----

 1018  wget https://dl.google.com/cloudsql/cloud_sql_proxy.linux.amd64 -O cloud_sql_proxy
 1019  ls -l
 1020  chmod +x cloud_sql_proxy
 1021  curl -o cloud_sql_proxy https://dl.google.com/cloudsql/cloud_sql_proxy.darwin.amd64
 1022  chmod +x cloud_sql_proxy
 1023  gcloud sql instances describe pg-instance \\n  --project=apigee-test-0002-demo \\n  --format='value(connectionName)'\n
 1024  ./cloud_sql_proxy \\n  -instances=apigee-test-0002-demo:us-central1:pg-instance=tcp:5432 \\n  --project=apigee-test-0002-demo\n
 1025  ./cloud_sql_proxy \\n  -instances=apigee-test-0002-demo:us-central1:pg-instance=tcp:5432\n

 ------


 Step 1 — Run this inside psql on testdb
sql
Copy
Edit
GRANT INSERT, SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
ON TABLE public.customers TO appuser;

GRANT INSERT, SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
ON TABLE public.products TO appuser;

GRANT INSERT, SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
ON TABLE public.orders TO appuser;

GRANT INSERT, SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
ON TABLE public.order_items TO appuser;
Step 2 — Also grant on sequences (needed for SERIAL / ID columns)
sql
Copy
Edit
GRANT USAGE, SELECT, UPDATE ON SEQUENCE public.customers_customer_id_seq TO appuser;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE public.products_product_id_seq TO appuser;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE public.orders_order_id_seq TO appuser;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE public.order_items_order_item_id_seq TO appuser;
(Adjust sequence names if yours differ — you can check with \ds in psql.)

Step 3 — Verify
sql
Copy
Edit
SELECT grantee, privilege_type, table_schema, table_name
FROM information_schema.role_table_grants
WHERE grantee = 'appuser';
-------


apiVersion: run.googleapis.com/v1
kind: Job
metadata:
  name: sql-connectivity-checks-job
  namespace: '741169614600'
  selfLink: /apis/run.googleapis.com/v1/namespaces/741169614600/jobs/sql-connectivity-checks-job
  uid: 6194b27c-0660-4766-8ffb-7175c8322b66
  resourceVersion: AAY8T3g3a64
  generation: 1
  creationTimestamp: '2025-08-14T08:27:41.339213Z'
  labels:
    cloud.googleapis.com/location: us-central1
    run.googleapis.com/lastUpdatedTime: '2025-08-14T08:27:41.339213Z'
  annotations:
    run.googleapis.com/client-name: gcloud
    run.googleapis.com/client-version: 534.0.0
    run.googleapis.com/creator: master@apigee-test-0002-demo.iam.gserviceaccount.com
    run.googleapis.com/lastModifier: master@apigee-test-0002-demo.iam.gserviceaccount.com
    run.googleapis.com/operation-id: 1377a8c7-4ce0-4574-99cd-b1b12142bc0a
spec:
  template:
    metadata:
      labels:
        client.knative.dev/nonce: gug_wol_seh
      annotations:
        run.googleapis.com/client-name: gcloud
        run.googleapis.com/client-version: 534.0.0
        run.googleapis.com/vpc-access-egress: private-ranges-only
        run.googleapis.com/execution-environment: gen2
        run.googleapis.com/vpc-access-connector: projects/apigee-test-0002-demo/locations/us-central1/connectors/cloud-run-vpc-connector
    spec:
      taskCount: 1
      template:
        spec:
          containers:
          - image: gcr.io/apigee-test-0002-demo/sql-connectivity-check
            env:
            - name: DB_HOST
              value: 10.15.68.5
            - name: DB_PORT
              value: '5432'
            - name: DB_NAME
              value: testdb
            - name: DB_USER
              value: pgadmin
            - name: DB_SSLMODE
              value: verify-ca
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  key: latest
                  name: pg-admin-user-password
            - name: DB_SSL_CERT
              valueFrom:
                secretKeyRef:
                  key: latest
                  name: pg-client-cert
            - name: DB_SSL_KEY
              valueFrom:
                secretKeyRef:
                  key: latest
                  name: pg-client-private-key
            - name: DB_SSL_ROOTCERT
              valueFrom:
                secretKeyRef:
                  key: latest
                  name: pg-server-ca-cert
            resources:
              limits:
                memory: 512Mi
                cpu: 1000m
          maxRetries: 3
          timeoutSeconds: '600'
          serviceAccountName: 741169614600-compute@developer.gserviceaccount.com
status:
  observedGeneration: 1
  conditions:
  - type: Ready
    status: 'True'
    lastTransitionTime: '2025-08-14T08:27:41.743898Z'
  executionCount: 5
  latestCreatedExecution:
    name: sql-connectivity-checks-job-8gf76
    completionTimestamp: '2025-08-14T08:57:56.213445Z'
    creationTimestamp: '2025-08-14T08:56:16.862088Z'
    completionStatus: EXECUTION_SUCCEEDED
--------
check_db.py


import os
import psycopg2
import stat

def write_file_from_env(env_var, file_path, perm=0o600):
    value = os.getenv(env_var)
    if not value:
        raise ValueError(f"Missing environment variable: {env_var}")
    with open(file_path, "w") as f:
        f.write(value)
    os.chmod(file_path, perm)
    print(f"✅ Wrote {env_var} to {file_path}")

def connect_to_db():
    db_host = os.getenv("DB_HOST")
    db_port = os.getenv("DB_PORT", "5432")
    db_name = os.getenv("DB_NAME")
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD")
    ssl_mode = os.getenv("DB_SSLMODE", "verify-ca")

    ssl_cert = "/tmp/client.crt"
    ssl_key = "/tmp/client.key"
    ssl_rootcert = "/tmp/server-ca.crt"

    # Write secrets from env vars to files
    write_file_from_env("DB_SSL_CERT", ssl_cert)
    write_file_from_env("DB_SSL_KEY", ssl_key)
    write_file_from_env("DB_SSL_ROOTCERT", ssl_rootcert)

    print(f"🔍 Using SSL mode: {ssl_mode}")

    conn = psycopg2.connect(
        host=db_host,
        port=db_port,
        dbname=db_name,
        user=db_user,
        password=db_password,
        sslmode=ssl_mode,
        sslcert=ssl_cert,
        sslkey=ssl_key,
        sslrootcert=ssl_rootcert
    )
    print("✅ Connected successfully!")
    return conn

def check_user_privileges(conn, check_user):
    with conn.cursor() as cur:
        print(f"🔍 Checking privileges for user '{check_user}' on database '{os.getenv('DB_NAME')}'...")
        # Query privileges granted to the user on tables
        cur.execute("""
            SELECT grantee, privilege_type, table_schema, table_name
            FROM information_schema.role_table_grants
            WHERE grantee = %s;
        """, (check_user,))
        privileges = cur.fetchall()
        if privileges:
            for grantee, privilege, schema, table in privileges:
                print(f" - {grantee} has {privilege} on {schema}.{table}")
        else:
            print(f" - No table privileges found for user '{check_user}'.")

if __name__ == "__main__":
    connection = None
    try:
        connection = connect_to_db()
        check_user_privileges(connection, "appuser")  # Specify the user to check
    except Exception as e:
        print(f"❌ Failed: {e}")
    finally:
        if connection:
            connection.close()
  ------

FROM python:3.11-slim

WORKDIR /app
COPY check_db.py . 

# Install dependencies
RUN pip install psycopg2-binary

CMD ["python", "check_db.py"]
  
