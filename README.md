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
