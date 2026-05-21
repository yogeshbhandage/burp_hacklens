# -*- coding: utf-8 -*-
# ============================================================
#  burp_hacklens.py  -  HackLens Burp Suite Extension
#  Purpose : Passive secret scanner - JS / JSON / HTML / XML
#  Requires: Jython 2.7 standalone JAR
#  Install : Extender > Extensions > Add > Type: Python
# ============================================================

from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab, IHttpListener
from javax.swing import (JPanel, JScrollPane, JTable, JLabel,
                          JButton, JSplitPane, JTextArea, BoxLayout,
                          SwingUtilities)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Color, Font, Dimension
from java.awt.event import ActionListener
from java.lang import Runnable, Integer
import re
import threading

# ============================================================
#  SECRET PATTERNS  (150+)
# ============================================================
SECRET_PATTERNS = [

    # ---- AWS -----------------------------------------------
    {"name": "AWS_ACCESS_KEY_ID",
     "severity": "HIGH",
     "pattern": r"(?i)(AWS_ACCESS_KEY_ID|aws_access_key_id|AccessKeyId)\s*[:=,\"'\s]\s*[\"']?(AKIA[0-9A-Z]{16})[\"']?"},
    {"name": "AWS Access Key (bare)",
     "severity": "HIGH",
     "pattern": r"\bAKIA[0-9A-Z]{16}\b"},
    {"name": "AWS_SECRET_ACCESS_KEY",
     "severity": "CRITICAL",
     "pattern": r"(?i)(AWS_SECRET_ACCESS_KEY|SecretAccessKey)\s*[:=,\"'\s]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"},
    {"name": "AWS_SESSION_TOKEN",
     "severity": "HIGH",
     "pattern": r"(?i)(AWS_SESSION_TOKEN|AWSSessionToken|SessionToken)\s*[:=,\"'\s]\s*[\"']?([A-Za-z0-9/+=]{100,})[\"']?"},
    {"name": "AWS_MWS_AUTH_TOKEN",
     "severity": "HIGH",
     "pattern": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"},
    {"name": "AWS ARN",
     "severity": "MEDIUM",
     "pattern": r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s\"']+"},

    # ---- Azure ---------------------------------------------
    {"name": "AZURE_CLIENT_ID",
     "severity": "LOW",
     "pattern": r"(?i)(AZURE_CLIENT_ID|azure_client_id)\s*[:=]\s*[\"']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']"},
    {"name": "AZURE_CLIENT_SECRET",
     "severity": "CRITICAL",
     "pattern": r"(?i)(AZURE_CLIENT_SECRET|azure_client_secret)\s*[:=]\s*[\"']([A-Za-z0-9~.\-_]{34,40})[\"']"},
    {"name": "AZURE_STORAGE_KEY",
     "severity": "HIGH",
     "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86}=="},
    {"name": "AZURE_STORAGE_ACCOUNT_KEY",
     "severity": "HIGH",
     "pattern": r"(?i)(AZURE_STORAGE_ACCOUNT_KEY|AZURE_STORAGE_KEY)\s*[:=]\s*[\"']([A-Za-z0-9+/=]{86}==)[\"']"},
    {"name": "AZURE_SAS_TOKEN",
     "severity": "HIGH",
     "pattern": r"(?i)(AZURE_SAS_TOKEN|sas_token)\s*[:=]\s*[\"']([^\"']{20,512})[\"']"},

    # ---- Google / GCP --------------------------------------
    {"name": "GOOGLE_API_KEY",
     "severity": "HIGH",
     "pattern": r"AIza[0-9A-Za-z\-_]{35}"},
    {"name": "GOOGLE_CLIENT_ID",
     "severity": "LOW",
     "pattern": r"[0-9]{12}-[0-9a-z]{32}\.apps\.googleusercontent\.com"},
    {"name": "GOOGLE_CLIENT_SECRET",
     "severity": "CRITICAL",
     "pattern": r"(?i)(GOOGLE_CLIENT_SECRET|google_client_secret)\s*[:=]\s*[\"']([A-Za-z0-9\-_]{24})[\"']"},
    {"name": "GOOGLE_OAUTH_ACCESS_TOKEN",
     "severity": "HIGH",
     "pattern": r"ya29\.[0-9A-Za-z\-_]{60,}"},
    {"name": "GCP_SERVICE_ACCOUNT",
     "severity": "CRITICAL",
     "pattern": r"\"type\"\s*:\s*\"service_account\""},
    {"name": "Firebase API Key",
     "severity": "MEDIUM",
     "pattern": r"(?i)(firebase[_\-]?api[_\-]?key)\s*[:=]\s*[\"']?(AIza[0-9A-Za-z\-_]{35})[\"']?"},
    {"name": "Firebase DB URL",
     "severity": "MEDIUM",
     "pattern": r"https://[a-z0-9\-]+\.firebaseio\.com"},

    # ---- GitHub / GitLab -----------------------------------
    {"name": "GITHUB_TOKEN / PAT",
     "severity": "HIGH",
     "pattern": r"ghp_[0-9A-Za-z]{36}"},
    {"name": "GitHub OAuth Token",
     "severity": "HIGH",
     "pattern": r"gho_[0-9A-Za-z]{36}"},
    {"name": "GITHUB_ACTIONS_TOKEN",
     "severity": "HIGH",
     "pattern": r"(ghu|ghs|ghr)_[0-9A-Za-z]{36}"},
    {"name": "GitHub Fine-Grained PAT",
     "severity": "HIGH",
     "pattern": r"github_pat_[0-9A-Za-z_]{82}"},
    {"name": "GITLAB_ACCESS_TOKEN",
     "severity": "HIGH",
     "pattern": r"glpat-[0-9A-Za-z\-_]{20}"},

    # ---- Stripe --------------------------------------------
    {"name": "STRIPE_SECRET_KEY",
     "severity": "CRITICAL",
     "pattern": r"sk_live_[0-9A-Za-z]{24,99}"},
    {"name": "Stripe Restricted Key",
     "severity": "HIGH",
     "pattern": r"rk_live_[0-9A-Za-z]{24,99}"},
    {"name": "STRIPE_PUBLISHABLE_KEY",
     "severity": "LOW",
     "pattern": r"pk_live_[0-9A-Za-z]{24,99}"},
    {"name": "STRIPE_API_KEY (test)",
     "severity": "INFO",
     "pattern": r"(sk|pk|rk)_test_[0-9A-Za-z]{24,99}"},

    # ---- PayPal / Braintree / Square -----------------------
    {"name": "PAYPAL_BRAINTREE_ACCESS_TOKEN",
     "severity": "HIGH",
     "pattern": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"},
    {"name": "SQUARE_ACCESS_TOKEN",
     "severity": "HIGH",
     "pattern": r"sq0atp-[0-9A-Za-z\-_]{22}"},
    {"name": "SQUARE_OAUTH_SECRET",
     "severity": "HIGH",
     "pattern": r"sq0csp-[0-9A-Za-z\-_]{43}"},
    {"name": "PAYPAL_CLIENT_SECRET",
     "severity": "CRITICAL",
     "pattern": r"(?i)(PAYPAL_CLIENT_SECRET|paypal_client_secret)\s*[:=]\s*[\"']([A-Za-z0-9\-_]{60,100})[\"']"},

    # ---- Slack ---------------------------------------------
    {"name": "SLACK_BOT_TOKEN",
     "severity": "HIGH",
     "pattern": r"xoxb-[0-9]{9,13}-[0-9]{9,13}-[0-9A-Za-z]{24}"},
    {"name": "SLACK_USER_TOKEN",
     "severity": "HIGH",
     "pattern": r"xoxp-[0-9]{9,13}-[0-9]{9,13}-[0-9]{9,13}-[0-9a-f]{32}"},
    {"name": "SLACK_WEBHOOK_URL",
     "severity": "HIGH",
     "pattern": r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"},
    {"name": "Slack Workspace Token",
     "severity": "HIGH",
     "pattern": r"xoxa-[0-9A-Za-z\-]{50,}"},

    # ---- Discord -------------------------------------------
    {"name": "DISCORD_WEBHOOK_URL",
     "severity": "HIGH",
     "pattern": r"https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+"},
    {"name": "DISCORD_TOKEN",
     "severity": "HIGH",
     "pattern": r"(?i)(DISCORD_TOKEN|discord_token)\s*[:=]\s*[\"']([MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27})[\"']"},

    # ---- Twilio --------------------------------------------
    {"name": "TWILIO_ACCOUNT_SID",
     "severity": "MEDIUM",
     "pattern": r"(?i)(TWILIO_ACCOUNT_SID|twilio_account_sid|AccountSid)\s*[:=,\"'\s]\s*[\"']?(AC[a-zA-Z0-9]{32})[\"']?"},
    {"name": "TWILIO_AUTH_TOKEN",
     "severity": "HIGH",
     "pattern": r"(?i)(TWILIO_AUTH_TOKEN|twilio_auth_token)\s*[:=]\s*[\"']([a-zA-Z0-9]{32})[\"']"},

    # ---- Email / SMTP --------------------------------------
    {"name": "SENDGRID_API_KEY",
     "severity": "HIGH",
     "pattern": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"},
    {"name": "MAILGUN_API_KEY",
     "severity": "HIGH",
     "pattern": r"(?i)(MAILGUN_API_KEY|mailgun_api_key|mailgun_key)\s*[:=]\s*[\"']?(key-[0-9a-zA-Z]{32})[\"']?"},
    {"name": "Mailchimp API Key",
     "severity": "HIGH",
     "pattern": r"(?i)(MAILCHIMP_API_KEY|mailchimp_api_key|mc_api_key)\s*[:=]\s*[\"']?([0-9a-f]{32}-us[0-9]{1,2})[\"']?"},
    {"name": "SMTP_USERNAME",
     "severity": "MEDIUM",
     "pattern": r"(?i)(SMTP_USERNAME|SMTP_USER|MAIL_USERNAME)\s*[:=]\s*[\"']([^\"'@\s]{2,64}@[^\"'\s]{2,64})[\"']"},
    {"name": "SMTP_PASSWORD / MAIL_PASSWORD",
     "severity": "HIGH",
     "pattern": r"(?i)(SMTP_PASSWORD|SMTP_PASS|MAIL_PASSWORD|MAIL_PASS|MAILER_PASSWORD)\s*[:=]\s*[\"']([^\"']{6,128})[\"']"},

    # ---- Monitoring ----------------------------------------
    {"name": "SENTRY_DSN",
     "severity": "MEDIUM",
     "pattern": r"https://[0-9a-f]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+"},
    {"name": "DATADOG_API_KEY",
     "severity": "HIGH",
     "pattern": r"(?i)(DATADOG_API_KEY|DD_API_KEY)\s*[:=]\s*[\"']([a-f0-9]{32})[\"']"},
    {"name": "NEW_RELIC_LICENSE_KEY",
     "severity": "HIGH",
     "pattern": r"(?i)(NEW_RELIC_LICENSE_KEY|newrelic_license_key)\s*[:=]\s*[\"']([A-Za-z0-9]{40})[\"']"},

    # ---- Heroku --------------------------------------------
    {"name": "HEROKU_API_KEY",
     "severity": "HIGH",
     "pattern": r"(?i)(HEROKU_API_KEY)\s*[:=]\s*[\"']([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})[\"']"},
    {"name": "HEROKU_AUTHORIZATION",
     "severity": "HIGH",
     "pattern": r"(?i)(HEROKU_AUTHORIZATION)\s*[:=]\s*[\"']([A-Za-z0-9\-_]{20,60})[\"']"},

    # ---- Social / OAuth ------------------------------------
    {"name": "FACEBOOK_ACCESS_TOKEN",
     "severity": "HIGH",
     "pattern": r"(?i)(FACEBOOK_ACCESS_TOKEN|facebook_access_token|fb_access_token|fbAccessToken)\s*[:=]\s*[\"']?(EAA[A-Za-z0-9]{80,})[\"']?"},
    {"name": "TWITTER_ACCESS_TOKEN",
     "severity": "HIGH",
     "pattern": r"(?i)(TWITTER_ACCESS_TOKEN)\s*[:=]\s*[\"']([0-9]+-[A-Za-z0-9]{40})[\"']"},
    {"name": "TWITTER_OAUTH_TOKEN",
     "severity": "HIGH",
     "pattern": r"(?i)(TWITTER_OAUTH_TOKEN)\s*[:=]\s*[\"']([A-Za-z0-9\-_]{40,80})[\"']"},

    # ---- Database connections ------------------------------
    {"name": "DATABASE_URL / MONGODB_URI (with creds)",
     "severity": "HIGH",
     "pattern": r"(mongodb(\+srv)?|postgres(ql)?|mysql|redis|mssql)://[^:\"'\s]{1,64}:[^@\"'\s]{4,128}@[^\s\"'<>]{4,256}"},
    {"name": "PGPASSWORD",
     "severity": "HIGH",
     "pattern": r"(?i)(PGPASSWORD)\s*[:=]\s*[\"']([^\"']{4,128})[\"']"},
    {"name": "MySQL Password",
     "severity": "HIGH",
     "pattern": r"(?i)(mysql_password|MYSQL_PASSWORD|mysql_pass|DB_PASSWORD|DB_PASS)\s*[:=]\s*[\"']([^\"']{4,128})[\"']"},
    {"name": "MySQL Username",
     "severity": "MEDIUM",
     "pattern": r"(?i)(mysql_username|MYSQL_USERNAME|mysql_user|MYSQL_USER|DB_USERNAME|DB_USER)\s*[:=]\s*[\"']([^\"']{2,64})[\"']"},
    {"name": "MySQL Server/Host",
     "severity": "LOW",
     "pattern": r"(?i)(mysql_server|MYSQL_SERVER|mysql_host|MYSQL_HOST|DB_HOST)\s*[:=]\s*[\"']([^\"']{4,256})[\"']"},
    {"name": "Redis Password",
     "severity": "HIGH",
     "pattern": r"(?i)(REDIS_PASSWORD|REDIS_PASS|redis_password)\s*[:=]\s*[\"']([^\"']{4,128})[\"']"},

    # ---- JWT in response body (NOT auth header) ------------
    # Tightened: require JSON string context ("token":"eyJ...") and longer segments
    {"name": "JWT (response body)",
     "severity": "HIGH",
     "pattern": r"[\"'](eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})[\"']"},

    # ---- OAuth / Session tokens ----------------------------
    {"name": "OAUTH_TOKEN",
     "severity": "HIGH",
     "pattern": r"(?i)(OAUTH_TOKEN|oauth_token|oauthToken)\s*[:=]\s*[\"']([A-Za-z0-9\-_.+/=]{20,512})[\"']"},
    {"name": "OAUTH_CLIENT_ID",
     "severity": "LOW",
     "pattern": r"(?i)(OAUTH_CLIENT_ID|oauth_client_id)\s*[:=]\s*[\"']([A-Za-z0-9\-_]{8,128})[\"']"},
    {"name": "OAUTH_CLIENT_SECRET",
     "severity": "CRITICAL",
     "pattern": r"(?i)(OAUTH_CLIENT_SECRET|oauth_client_secret)\s*[:=]\s*[\"']([A-Za-z0-9\-_]{16,256})[\"']"},
    {"name": "ACCESS_TOKEN",
     "severity": "HIGH",
     "pattern": r"(?i)(ACCESS_TOKEN|access_token|accessToken)\s*[:=]\s*[\"']([A-Za-z0-9\-_.+/=]{20,512})[\"']"},
    {"name": "REFRESH_TOKEN",
     "severity": "HIGH",
     "pattern": r"(?i)(REFRESH_TOKEN|refresh_token|refreshToken)\s*[:=]\s*[\"']([A-Za-z0-9\-_.+/=]{20,512})[\"']"},
    {"name": "BEARER_TOKEN",
     "severity": "HIGH",
     "pattern": r"(?i)(BEARER_TOKEN|bearer_token|bearerToken)\s*[:=]\s*[\"']([A-Za-z0-9\-_.+/=]{20,512})[\"']"},
    {"name": "SESSION_ID",
     "severity": "MEDIUM",
     "pattern": r"(?i)(SESSION_ID|session_id|sessionId|PHPSESSID|JSESSIONID)\s*[:=]\s*[\"']([A-Za-z0-9\-_]{20,256})[\"']"},
    # ---- Generic API / Secret keys -------------------------
    {"name": "API_KEY",
     "severity": "MEDIUM",
     "pattern": r"(?i)(API_KEY|api_key)\s*[:=]\s*[\"']([A-Za-z0-9\-_]{20,128})[\"']"},
    {"name": "SECRET_KEY",
     "severity": "HIGH",
     "pattern": r"(?i)(SECRET_KEY|secret_key|DJANGO_SECRET_KEY|FLASK_SECRET|APP_SECRET_KEY)\s*[:=]\s*[\"']([A-Za-z0-9\-_!@#$%^&*+/=]{12,256})[\"']"},
    {"name": "APP_SECRET",
     "severity": "HIGH",
     "pattern": r"(?i)(APP_SECRET|app_secret|APP_KEY|app_key)\s*[:=]\s*[\"']([A-Za-z0-9\-_+/=]{16,256})[\"']"},
    {"name": "CLIENT_SECRET",
     "severity": "CRITICAL",
     "pattern": r"(?i)(CLIENT_SECRET|client_secret)\s*[:=]\s*[\"']([A-Za-z0-9\-_]{16,256})[\"']"},
    {"name": "Encryption Password",
     "severity": "CRITICAL",
     "pattern": r"(?i)(encryption_password|ENCRYPTION_PASSWORD|encryptionPassword|encrypt_pass)\s*[:=]\s*[\"']([^\"']{6,256})[\"']"},
    {"name": "Admin Password",
     "severity": "CRITICAL",
     "pattern": r"(?i)(ADMIN_PASSWORD|admin_password|adminPassword|ADMIN_PASS)\s*[:=]\s*[\"']([^\"']{4,128})[\"']"},
    # Tightened: value must be password-like chars only (no parens/commas/spaces)
    # Prevents FP on JS label text like r(23,"XYZ Password: "),m(),u(24,...
    {"name": "Password in Code (assignment)",
     "severity": "MEDIUM",
     "pattern": r"(?i)\b(password|passwd|pwd)\s*[:=]\s*[\"']([A-Za-z0-9\-_!@#$%^&*+./]{6,128})[\"']"},
    {"name": "Password in Code (JSON)",
     "severity": "MEDIUM",
     "pattern": r"(?i)[\"']password[\"']\s*:\s*[\"']([A-Za-z0-9\-_!@#$%^&*+./]{6,128})[\"']"},
    {"name": "Engine Server",
     "severity": "LOW",
     "pattern": r"(?i)(ENGINE_SERVER|engine_server|engineServer|ENGINE_HOST|engine_host)\s*[:=]\s*[\"']([^\"']{4,256})[\"']"},
    {"name": "Webhook Secret",
     "severity": "HIGH",
     "pattern": r"(?i)(WEBHOOK_SECRET|webhook_secret|webhookSecret)\s*[:=]\s*[\"']([A-Za-z0-9\-_]{8,256})[\"']"},
    {"name": "Cookie / Session Secret",
     "severity": "HIGH",
     "pattern": r"(?i)(COOKIE_SECRET|cookie_secret|cookieSecret|SESSION_SECRET|session_secret|sessionSecret)\s*[:=]\s*[\"']([A-Za-z0-9\-_]{8,256})[\"']"},
    {"name": "Signing Key / JWT Secret",
     "severity": "HIGH",
     "pattern": r"(?i)(SIGNING_KEY|signing_key|signingKey|JWT_SECRET|jwt_secret|jwtSecret|SIGN_SECRET|sign_secret)\s*[:=]\s*[\"']([A-Za-z0-9\-_+/=]{8,256})[\"']"},
    {"name": "HMAC_SECRET",
     "severity": "HIGH",
     "pattern": r"(?i)(HMAC_SECRET|hmac_secret|hmacSecret|HMAC_KEY|hmac_key)\s*[:=]\s*[\"']([A-Za-z0-9\-_+/=]{16,256})[\"']"},
    {"name": "MASTER_KEY",
     "severity": "CRITICAL",
     "pattern": r"(?i)(MASTER_KEY|master_key|MASTER_SECRET|master_secret|ROOT_KEY|root_key)\s*[:=]\s*[\"']([A-Za-z0-9\-_+/=]{16,256})[\"']"},

    # ---- Crypto Keys / IV ----------------------------------
    {"name": "AES_KEY",
     "severity": "CRITICAL",
     "pattern": r"(?i)(AES_KEY|aes_key|aesKey|AES_SECRET|CIPHER_KEY|cipher_key|ENCRYPT_KEY|ENCRYPTION_KEY)\s*[:=]\s*[\"']([A-Za-z0-9+/=\-_]{16,512})[\"']"},
    {"name": "AES IV / Initialization Vector",
     "severity": "HIGH",
     "pattern": r"(?i)(aes_iv|AES_IV|iv_key|IV_KEY|initialization_vector|initVector|ivKey|IV)\s*[:=]\s*[\"']([0-9a-fA-F]{16,64})[\"']"},
    {"name": "PBKDF / scrypt key material",
     "severity": "HIGH",
     "pattern": r"(?i)(PBKDF_SECRET|PBKDF_PASS|SCRYPT_SECRET|KDF_SECRET)\s*[:=]\s*[\"']([^\"']{8,256})[\"']"},

    # ---- Private Keys / Certificates -----------------------
    {"name": "RSA_PRIVATE_KEY",
     "severity": "CRITICAL",
     "pattern": r"-----BEGIN RSA PRIVATE KEY-----"},
    {"name": "EC_PRIVATE_KEY",
     "severity": "CRITICAL",
     "pattern": r"-----BEGIN EC PRIVATE KEY-----"},
    {"name": "DSA_PRIVATE_KEY",
     "severity": "CRITICAL",
     "pattern": r"-----BEGIN DSA PRIVATE KEY-----"},
    {"name": "PGP_PRIVATE_KEY",
     "severity": "CRITICAL",
     "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----"},
    {"name": "OPENSSH_PRIVATE_KEY",
     "severity": "CRITICAL",
     "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----"},
    {"name": "PRIVATE_KEY (generic)",
     "severity": "CRITICAL",
     "pattern": r"-----BEGIN PRIVATE KEY-----"},
    {"name": "CERTIFICATE",
     "severity": "LOW",
     "pattern": r"-----BEGIN CERTIFICATE-----"},

    # ---- UUID/GUID in sensitive context --------------------
    {"name": "UUID/GUID (sensitive key)",
     "severity": "LOW",
     "pattern": r"(?i)(api_key|apiKey|secret|token|account_id|user_id|session_id)\s*[:=]\s*[\"']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']"},

    # ---- Cloud / Infra extras ------------------------------
    {"name": "MAPBOX_API_KEY",
     "severity": "MEDIUM",
     "pattern": r"pk\.eyJ1IjoiW[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"},
    {"name": "Algolia API Key",
     "severity": "HIGH",
     "pattern": r"(?i)(ALGOLIA_API_KEY|X-Algolia-API-Key)\s*[:=]\s*[\"']([A-Za-z0-9]{32})[\"']"},
    {"name": "Vault Token",
     "severity": "CRITICAL",
     "pattern": r"(?i)(VAULT_TOKEN)\s*[:=]\s*[\"']?(hvs\.[A-Za-z0-9]{24,}|s\.[A-Za-z0-9]{24,})[\"']?"},
    {"name": "Databricks Token",
     "severity": "HIGH",
     "pattern": r"dapi[a-f0-9]{28,36}"},
    {"name": "Kubernetes Secret",
     "severity": "CRITICAL",
     "pattern": r"(?i)(KUBE_TOKEN|K8S_TOKEN|KUBECONFIG_TOKEN)\s*[:=]\s*[\"']([A-Za-z0-9\-_.]{16,512})[\"']"},
    {"name": "npm Auth Token",
     "severity": "HIGH",
     "pattern": r"npm_[A-Za-z0-9]{36}"},
    {"name": "Shopify Token",
     "severity": "HIGH",
     "pattern": r"shp(at|pa|ss)_[0-9A-Fa-f]{32}"},
    {"name": "DigitalOcean Token",
     "severity": "HIGH",
     "pattern": r"(?i)(DIGITALOCEAN_TOKEN|DO_TOKEN)\s*[:=]\s*[\"']([A-Za-z0-9]{64})[\"']"},
    {"name": "Terraform Cloud Token",
     "severity": "HIGH",
     "pattern": r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_]{60,}"},
    {"name": "CircleCI Token",
     "severity": "HIGH",
     "pattern": r"(?i)(CIRCLE_TOKEN|CIRCLECI_TOKEN)\s*[:=]\s*[\"']([A-Za-z0-9]{40})[\"']"},

    # ---- LDAP / Internal -----------------------------------
    {"name": "LDAP Password",
     "severity": "CRITICAL",
     "pattern": r"(?i)(LDAP_PASSWORD|ldap_password|LDAP_PASS|ldap_pass|ldap_bind_pass)\s*[:=]\s*[\"']([^\"']{4,128})[\"']"},
    {"name": "Internal IPv4",
     "severity": "LOW",
     "pattern": r"(?<!\d)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)"},

    # ---- JS Object key:value patterns ----------------------
    {"name": "JS Object - secret/password",
     "severity": "MEDIUM",
     "pattern": r"(?i)[\"'](secret|apikey|api_key|auth_token|password|secretkey|privatekey|encryptionkey|encryption_password|mysql_password)[\"']\s*:\s*[\"']([^\"']{8,256})[\"']"},
    {"name": "JS Object - DB credential",
     "severity": "HIGH",
     "pattern": r"(?i)[\"'](db_pass|db_password|database_password|mysql_password|encryption_password|redis_password)[\"']\s*:\s*[\"']([^\"']{4,256})[\"']"},
    {"name": "JS Object - token",
     "severity": "MEDIUM",
     "pattern": r"(?i)[\"'](access_token|refresh_token|id_token|bearer_token|oauth_token)[\"']\s*:\s*[\"']([A-Za-z0-9\-_.+/=]{20,512})[\"']"},

    # ---- CamelCase catch-all variants ----------------------
    {"name": "apiKey (camelCase)",
     "severity": "MEDIUM",
     "pattern": r"(?<![A-Za-z])apiKey\s*[:=]\s*[\"']([A-Za-z0-9\-_]{16,128})[\"']"},
    {"name": "secretKey (camelCase)",
     "severity": "HIGH",
     "pattern": r"(?<![A-Za-z])secretKey\s*[:=]\s*[\"']([A-Za-z0-9\-_!@#$%^&*+/=]{8,256})[\"']"},
    {"name": "authToken (camelCase)",
     "severity": "MEDIUM",
     "pattern": r"(?<![A-Za-z])authToken\s*[:=]\s*[\"']([A-Za-z0-9\-_.+/=]{16,512})[\"']"},
    {"name": "clientSecret (camelCase)",
     "severity": "HIGH",
     "pattern": r"(?<![A-Za-z])clientSecret\s*[:=]\s*[\"']([A-Za-z0-9\-_]{16,256})[\"']"},
    {"name": "privateKey (camelCase)",
     "severity": "CRITICAL",
     "pattern": r"(?<![A-Za-z])privateKey\s*[:=]\s*[\"']([A-Za-z0-9\-_+/=]{16,512})[\"']"},
    {"name": "encryptionKey (camelCase)",
     "severity": "CRITICAL",
     "pattern": r"(?<![A-Za-z])encryptionKey\s*[:=]\s*[\"']([A-Za-z0-9\-_+/=]{16,256})[\"']"},
    {"name": "dbPassword (camelCase)",
     "severity": "HIGH",
     "pattern": r"(?<![A-Za-z])dbPassword\s*[:=]\s*[\"']([^\"']{4,128})[\"']"},
    {"name": "accessToken (camelCase)",
     "severity": "HIGH",
     "pattern": r"(?<![A-Za-z])accessToken\s*[:=]\s*[\"']([A-Za-z0-9\-_.+/=]{16,512})[\"']"},
    {"name": "jwtSecret (camelCase)",
     "severity": "HIGH",
     "pattern": r"(?<![A-Za-z])jwtSecret\s*[:=]\s*[\"']([A-Za-z0-9\-_]{12,256})[\"']"},
    {"name": "webhookSecret (camelCase)",
     "severity": "HIGH",
     "pattern": r"(?<![A-Za-z])webhookSecret\s*[:=]\s*[\"']([A-Za-z0-9\-_]{8,256})[\"']"},
    {"name": "signingSecret (camelCase)",
     "severity": "HIGH",
     "pattern": r"(?<![A-Za-z])signingSecret\s*[:=]\s*[\"']([A-Za-z0-9\-_]{8,256})[\"']"},
    {"name": "cookieSecret (camelCase)",
     "severity": "HIGH",
     "pattern": r"(?<![A-Za-z])cookieSecret\s*[:=]\s*[\"']([A-Za-z0-9\-_]{8,256})[\"']"},
    {"name": "sessionSecret (camelCase)",
     "severity": "HIGH",
     "pattern": r"(?<![A-Za-z])sessionSecret\s*[:=]\s*[\"']([A-Za-z0-9\-_]{8,256})[\"']"},
    {"name": "refreshToken (camelCase)",
     "severity": "HIGH",
     "pattern": r"(?<![A-Za-z])refreshToken\s*[:=]\s*[\"']([A-Za-z0-9\-_.+/=]{16,512})[\"']"},

    # ---- Sensitive file exposure ---------------------------
    {"name": ".env file exposure",
     "severity": "HIGH",
     "pattern": r"(?i)(href|src|url|path)\s*[=:]\s*[\"'][^\"']*\.env[\"']"},
    {"name": ".git exposure",
     "severity": "HIGH",
     "pattern": r"(?i)(href|src|url|path)\s*[=:]\s*[\"'][^\"']*\.git(/|[\"'])"},

    # ---- Hardcoded Default / Weak Credentials --------------
    # skip_fp=True bypasses _is_fp so short values like "admin" are not filtered
    {"name": "Hardcoded Default Credential (password key)",
     "severity": "HIGH",
     "skip_fp": True,
     "pattern": r"(?i)\b(password|passwd|pwd)\s*[:=]\s*[\"'](admin|password|password123|123456|12345678|1234567890|qwerty|abc123|letmein|welcome|welcome1|monkey|dragon|master|root|toor|pass|1q2w3e4r|admin123|test123|guest|default|changeme|secret|login|pass123|administrator|passw0rd|p@ssword|p@ss123|admin@123)[\"']"},
    {"name": "Hardcoded Default Credential (JSON)",
     "severity": "HIGH",
     "skip_fp": True,
     "pattern": r"(?i)[\"']password[\"']\s*:\s*[\"'](admin|password|password123|123456|12345678|1234567890|qwerty|abc123|letmein|welcome|welcome1|monkey|dragon|master|root|toor|pass|1q2w3e4r|admin123|test123|guest|default|changeme|secret|login|pass123|administrator|passw0rd|p@ssword|p@ss123|admin@123)[\"']"},
    {"name": "Hardcoded Default Username",
     "severity": "MEDIUM",
     "skip_fp": True,
     "pattern": r"(?i)\b(username|user|login|uname)\s*[:=]\s*[\"'](admin|root|test|guest|administrator|superuser|sysadmin|operator)[\"']"},
]

# ============================================================
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Global dedup - persists for entire Burp session
_GLOBAL_SEEN      = set()
_GLOBAL_SEEN_LOCK = threading.Lock()


# ============================================================
#  FALSE POSITIVE FILTER
# ============================================================
_FP_EXACT = {
    "changeme", "change_me", "replace_me", "placeholder",
    "your-secret-here", "your_secret_here", "enter_key_here",
    "secret", "password", "pass", "passwd", "test", "example",
    "dummy", "sample", "none", "null", "undefined", "false", "true",
    "aaaaaaaaaa", "aaaaaaaaaaaaaaa", "1234567890", "12345678",
    "abcdefgh", "abcdefghij", "xxxxxxxx", "xxxxxxxxxxxxxxxxxxxx",
    "todo", "fixme", "<api-key>", "<secret>", "<your-key>",
    "<token>", "<password>", "key", "token", "value",
}

def _is_fp(value):
    v = value.strip().lower()
    if len(v) < 6:
        return True
    if v in _FP_EXACT:
        return True
    # All same character (e.g. "aaaaaa", "000000")
    if len(set(v)) <= 2:
        return True
    # Pure sequential digits
    if re.match(r'^[0-9]+$', v) and len(v) < 12:
        return True
    # Pure alphabetical / hyphenated words (e.g. "Passwort", "Wachtwoord",
    # "Mot de passe", "Palavra-passe") - these are i18n translation labels,
    # not real secrets. Real passwords always contain a digit or special char.
    if re.match(r'^[A-Za-z][A-Za-z\s\-]{4,28}$', v):
        return True
    return False


# ============================================================
#  SCAN ENGINE
# ============================================================
class SecretFinding(object):
    def __init__(self, name, severity, matched_value, url, context_line):
        self.name          = name
        self.severity      = severity
        self.matched_value = matched_value
        self.url           = url
        self.context_line  = context_line
        self.http_message  = None   # set after scan; holds IHttpRequestResponse


def scan_body_for_secrets(body_str, url):
    findings = []
    seen     = set()

    for p in SECRET_PATTERNS:
        try:
            matches = re.findall(p["pattern"], body_str)
        except re.error:
            continue

        for m in matches:
            value = m[-1] if isinstance(m, tuple) else m
            value = value.strip() if value else ""
            if not value:
                continue
            # skip_fp=True patterns bypass the FP filter (e.g. default credentials)
            if not p.get("skip_fp", False) and _is_fp(value):
                continue

            key = (p["name"], value[:80])
            if key in seen:
                continue
            seen.add(key)

            idx = body_str.find(value)
            if idx != -1:
                start   = max(0, idx - 60)
                end     = min(len(body_str), idx + len(value) + 100)
                context = body_str[start:end].strip().replace("\n", " ")
            else:
                context = ""

            findings.append(SecretFinding(
                name          = p["name"],
                severity      = p["severity"],
                matched_value = value[:120],
                url           = url,
                context_line  = context[:300],
            ))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings


# ============================================================
#  BURP SCAN ISSUE
#  FIX: proper HTML so each field renders on its own line
# ============================================================
class HackLensIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, finding):
        self._http_service  = http_service
        self._url           = url
        self._http_messages = http_messages
        self._finding       = finding

    def getUrl(self):        return self._url
    def getIssueName(self):  return "[HackLens] " + self._finding.name
    def getIssueType(self):  return 0x08000000

    def getSeverity(self):
        m = {"CRITICAL": "High", "HIGH": "High",
             "MEDIUM": "Medium", "LOW": "Low", "INFO": "Information"}
        return m.get(self._finding.severity, "Information")

    def getConfidence(self): return "Tentative"
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None

    def getIssueDetail(self):
        # No <code> tags - plain text matches Burp's default advisory font size
        return (
            "<table cellpadding='6'>"
            "<tr><td width='130'><b>Secret Type</b></td>"
            "<td>{}</td></tr>"
            "<tr><td><b>Severity</b></td>"
            "<td>{}</td></tr>"
            "<tr><td><b>Matched Value</b></td>"
            "<td><b><font color='#cc0000'>{}</font></b></td></tr>"
            "<tr><td><b>URL</b></td>"
            "<td>{}</td></tr>"
            "<tr><td valign='top'><b>Context</b></td>"
            "<td>{}</td></tr>"
            "</table>"
        ).format(
            self._finding.name,
            self._finding.severity,
            self._finding.matched_value,
            self._finding.url,
            self._finding.context_line,
        )

    def getRemediationDetail(self):
        return (
            "<ol>"
            "<li>Remove this secret from all client-side code immediately.</li>"
            "<li>Rotate / revoke the credential on the provider dashboard.</li>"
            "<li>Store secrets server-side only (env vars or a secrets manager).</li>"
            "<li>Audit git history for any previous exposure (truffleHog / gitleaks).</li>"
            "</ol>"
        )

    def getHttpMessages(self): return self._http_messages
    def getHttpService(self):  return self._http_service


# ============================================================
#  CUSTOM TABLE MODEL
#  FIX: returns Integer.class for column 0 so JTable sorts
#       1, 2, 3 ... 10, 11  (numeric) not 1, 10, 11, 2 (lexical)
# ============================================================
class HackLensTableModel(DefaultTableModel):
    _COL_NAMES = ["#", "Severity", "Secret Type", "Matched Value", "URL"]

    def __init__(self):
        DefaultTableModel.__init__(self, self._COL_NAMES, 0)

    def getColumnClass(self, col):
        # Returning Integer class makes the sorter treat col-0 as numeric
        if col == 0:
            return Integer
        return DefaultTableModel.getColumnClass(self, col)

    def isCellEditable(self, row, col):
        return False


# ============================================================
#  UI TAB
# ============================================================
class HackLensTab(ITab):

    def __init__(self, callbacks):
        self._callbacks  = callbacks
        self._helpers    = callbacks.getHelpers()
        self._findings   = []
        self._lock       = threading.Lock()
        self._build_ui()

    def _build_ui(self):
        from javax.swing.event import ListSelectionListener
        from java.awt.event    import MouseAdapter
        from javax.swing.text  import DefaultHighlighter
        from javax.swing       import JDialog, JTabbedPane, JSeparator

        self._table_model = HackLensTableModel()
        self._table       = JTable(self._table_model)
        self._table.setAutoCreateRowSorter(True)
        self._table.setFillsViewportHeight(True)
        self._table.setRowHeight(20)

        cm = self._table.getColumnModel()
        cm.getColumn(0).setMaxWidth(50)
        cm.getColumn(0).setMinWidth(30)
        cm.getColumn(1).setMaxWidth(80)
        cm.getColumn(3).setPreferredWidth(260)

        # ------ Detail pane (bottom) ---------------------------------------------------------------------------------------
        self._detail = JTextArea()
        self._detail.setEditable(False)
        self._detail.setFont(Font("Monospaced", Font.PLAIN, 13))
        self._detail.setForeground(Color.BLACK)
        self._detail.setBackground(Color.WHITE)
        self._detail.setLineWrap(True)
        self._detail.setWrapStyleWord(True)

        # Orange highlight - clearly visible with black text
        self._highlighter = DefaultHighlighter()
        self._hl_painter  = DefaultHighlighter.DefaultHighlightPainter(
            Color(255, 140, 0))
        self._detail.setHighlighter(self._highlighter)

        table        = self._table
        detail       = self._detail
        highlighter  = self._highlighter
        hl_painter   = self._hl_painter
        findings_ref = self._findings
        callbacks_ref = self._callbacks
        helpers_ref   = self._helpers

        # ------ Row selection --- fill detail + highlight ------------------------------
        class RowSel(ListSelectionListener):
            def valueChanged(self, e):
                if e.getValueIsAdjusting():
                    return
                row = table.getSelectedRow()
                if row < 0:
                    return
                mr = table.convertRowIndexToModel(row)
                if mr >= len(findings_ref):
                    return
                f = findings_ref[mr]
                text = (
                    "Secret Type  : {}\n"
                    "Severity     : {}\n"
                    "URL          : {}\n"
                    "Matched      : {}\n"
                    "\n"
                    "Context      :\n"
                    "{}\n"
                ).format(f.name, f.severity, f.url,
                         f.matched_value, f.context_line)
                detail.setText(text)
                detail.setCaretPosition(0)
                # highlight every occurrence of matched value
                highlighter.removeAllHighlights()
                needle = f.matched_value
                if needle:
                    start = 0
                    while True:
                        idx = text.find(needle, start)
                        if idx == -1:
                            break
                        try:
                            highlighter.addHighlight(
                                idx, idx + len(needle), hl_painter)
                        except Exception:
                            pass
                        start = idx + 1

        self._table.getSelectionModel().addListSelectionListener(RowSel())

        # ------ Double-click --- Request / Response popup ------------------------------
        tab = self
        class DblClick(MouseAdapter):
            def mouseClicked(self, e):
                if e.getClickCount() < 2:
                    return
                row = table.getSelectedRow()
                if row < 0:
                    return
                mr = table.convertRowIndexToModel(row)
                if mr >= len(findings_ref):
                    return
                f = findings_ref[mr]
                if f.http_message is None:
                    return
                SwingUtilities.invokeLater(
                    _RunnableWrapper(lambda: tab._show_popup(f)))

        self._table.addMouseListener(DblClick())

        # ------ Toolbar buttons ------------------------------------------------------------------------------------------------------
        clear_btn    = JButton("Clear All")
        export_btn   = JButton("Export to Output")
        repeater_btn = JButton("Send to Repeater")
        self._stats  = JLabel(
            "  Findings: 0  |  Patterns: {}".format(len(SECRET_PATTERNS)))

        tb = self
        class CA(ActionListener):
            def actionPerformed(self, e):
                tb.clear_findings()

        class EA(ActionListener):
            def actionPerformed(self, e):
                tb.export_to_stdout()

        class RA(ActionListener):
            def actionPerformed(self, e):
                row = table.getSelectedRow()
                if row < 0:
                    return
                mr = table.convertRowIndexToModel(row)
                if mr >= len(findings_ref):
                    return
                f = findings_ref[mr]
                if f.http_message is None:
                    return
                svc     = f.http_message.getHttpService()
                request = f.http_message.getRequest()
                use_https = (svc.getProtocol().lower() == "https")
                callbacks_ref.sendToRepeater(
                    svc.getHost(), svc.getPort(),
                    use_https, request,
                    "[HackLens] " + f.name)

        clear_btn.addActionListener(CA())
        export_btn.addActionListener(EA())
        repeater_btn.addActionListener(RA())

        toolbar = JPanel()
        toolbar.setLayout(BoxLayout(toolbar, BoxLayout.X_AXIS))
        toolbar.add(clear_btn)
        toolbar.add(export_btn)
        toolbar.add(repeater_btn)
        toolbar.add(self._stats)

        top    = JScrollPane(self._table)
        bottom = JScrollPane(self._detail)
        top.setPreferredSize(Dimension(900, 300))
        bottom.setPreferredSize(Dimension(900, 180))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top, bottom)
        split.setResizeWeight(0.65)

        header = JLabel(
            "  HackLens  |  Passive Secret Scanner  |  {} patterns"
            "  |  Double-click row = Request/Response popup".format(
                len(SECRET_PATTERNS)))
        header.setFont(Font("SansSerif", Font.BOLD, 13))
        header.setForeground(Color(30, 100, 180))

        self._panel = JPanel(BorderLayout())
        self._panel.add(header,  BorderLayout.NORTH)
        self._panel.add(split,   BorderLayout.CENTER)
        self._panel.add(toolbar, BorderLayout.SOUTH)

    # ------ Popup dialog: Request + Response tabs ---------------------------------------------------
    def _show_popup(self, finding):
        from javax.swing import JDialog, JTabbedPane, JScrollPane

        msg      = finding.http_message
        svc      = msg.getHttpService()
        req_bytes  = msg.getRequest()
        resp_bytes = msg.getResponse()

        req_str  = self._helpers.bytesToString(req_bytes)  if req_bytes  else "(no request)"
        resp_str = self._helpers.bytesToString(resp_bytes) if resp_bytes else "(no response)"

        # Request pane
        req_area = JTextArea(req_str)
        req_area.setEditable(False)
        req_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        req_area.setLineWrap(True)
        req_area.setWrapStyleWord(True)

        # Response pane with matched value highlighted
        resp_area = JTextArea(resp_str)
        resp_area.setEditable(False)
        resp_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        resp_area.setForeground(Color.BLACK)
        resp_area.setBackground(Color.WHITE)
        resp_area.setLineWrap(True)
        resp_area.setWrapStyleWord(True)

        from javax.swing.text import DefaultHighlighter
        hl       = DefaultHighlighter()
        hl_paint = DefaultHighlighter.DefaultHighlightPainter(Color(255, 140, 0))
        resp_area.setHighlighter(hl)
        needle = finding.matched_value
        first_hit = -1
        if needle:
            start = 0
            while True:
                idx = resp_str.find(needle, start)
                if idx == -1:
                    break
                try:
                    hl.addHighlight(idx, idx + len(needle), hl_paint)
                    if first_hit == -1:
                        first_hit = idx
                except Exception:
                    pass
                start = idx + 1
        # Scroll to first highlight in response
        if first_hit != -1:
            resp_area.setCaretPosition(first_hit)

        tabs = JTabbedPane()
        tabs.addTab("Request",  JScrollPane(req_area))
        tabs.addTab("Response", JScrollPane(resp_area))
        tabs.setSelectedIndex(1)  # show response tab by default

        title = "[HackLens] {} - {}".format(finding.name, svc.getHost())
        dialog = JDialog()
        dialog.setTitle(title)
        dialog.setSize(900, 650)
        dialog.setLocationRelativeTo(None)
        dialog.add(tabs)
        dialog.setVisible(True)

    def getTabCaption(self):  return "HackLens"
    def getUiComponent(self): return self._panel

    def add_findings(self, findings):
        with self._lock:
            for f in findings:
                idx = len(self._findings) + 1
                self._findings.append(f)
                self._table_model.addRow([
                    Integer(idx),
                    f.severity,
                    f.name,
                    f.matched_value[:70],
                    f.url,
                ])
            self._stats.setText(
                "  Findings: {}  |  Patterns: {}".format(
                    len(self._findings), len(SECRET_PATTERNS)))

    def clear_findings(self):
        with self._lock:
            del self._findings[:]
            while self._table_model.getRowCount() > 0:
                self._table_model.removeRow(0)
            self._stats.setText(
                "  Findings: 0  |  Patterns: {}".format(len(SECRET_PATTERNS)))
            self._detail.setText("")
        with _GLOBAL_SEEN_LOCK:
            _GLOBAL_SEEN.clear()

    def export_to_stdout(self):
        with self._lock:
            print("\n=== HackLens Export - {} findings ===".format(
                len(self._findings)))
            for f in self._findings:
                print("[{}] {} | {} | {}".format(
                    f.severity, f.name, f.matched_value[:80], f.url))
            print("=== End ===\n")


# ============================================================
#  MAIN EXTENDER
# ============================================================
class BurpExtender(IBurpExtender, IScannerCheck, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("HackLens - Secret Scanner")
        self._tab = HackLensTab(callbacks)
        callbacks.addSuiteTab(self._tab)
        callbacks.registerScannerCheck(self)
        callbacks.registerHttpListener(self)
        callbacks.printOutput(
            "[HackLens] Ready - {} patterns loaded".format(len(SECRET_PATTERNS)))

    # ----------------------------------------------------------
    #  IHttpListener  - fires on EVERY proxy response
    #  Primary path: catches JS, JSON API, HTML, plain text
    # ----------------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        response = messageInfo.getResponse()
        if response is None:
            return

        analyzed    = self._helpers.analyzeResponse(response)
        body_offset = analyzed.getBodyOffset()
        body_bytes  = response[body_offset:]
        if not body_bytes:
            return

        content_type = ""
        for h in analyzed.getHeaders():
            if h.lower().startswith("content-type:"):
                content_type = h.lower()
                break

        SCAN_TYPES = (
            "javascript", "ecmascript", "html", "json", "text/",
            "application/json", "application/javascript",
            "application/x-javascript", "application/xml",
            "application/x-www-form-urlencoded",
        )
        if content_type and not any(t in content_type for t in SCAN_TYPES):
            return

        try:
            body_str = self._helpers.bytesToString(body_bytes)
        except Exception:
            return

        url      = str(self._helpers.analyzeRequest(messageInfo).getUrl())
        findings = scan_body_for_secrets(body_str, url)
        if not findings:
            return

        new_findings = []
        with _GLOBAL_SEEN_LOCK:
            for f in findings:
                key = (f.name, f.url, f.matched_value[:80])
                if key not in _GLOBAL_SEEN:
                    _GLOBAL_SEEN.add(key)
                    f.http_message = messageInfo
                    new_findings.append(f)

        if not new_findings:
            return

        nf = new_findings
        SwingUtilities.invokeLater(
            _RunnableWrapper(lambda: self._tab.add_findings(nf)))

        svc     = messageInfo.getHttpService()
        req_url = self._helpers.analyzeRequest(messageInfo).getUrl()
        for f in new_findings:
            self._callbacks.addScanIssue(HackLensIssue(
                http_service=svc, url=req_url,
                http_messages=[messageInfo], finding=f))

        self._callbacks.printOutput(
            "[HackLens] {} new secret(s) -> {}".format(len(new_findings), url))

    # ----------------------------------------------------------
    #  IScannerCheck  - passive (spider / active scan backup)
    # ----------------------------------------------------------
    def doPassiveScan(self, base_request_response):
        response = base_request_response.getResponse()
        if response is None:
            return []

        analyzed    = self._helpers.analyzeResponse(response)
        body_offset = analyzed.getBodyOffset()
        body_bytes  = response[body_offset:]

        content_type = ""
        for h in analyzed.getHeaders():
            if h.lower().startswith("content-type:"):
                content_type = h.lower()
                break

        if not any(t in content_type for t in
                   ("javascript", "ecmascript", "html",
                    "json", "text/", "application/")):
            return []

        try:
            body_str = self._helpers.bytesToString(body_bytes)
        except Exception:
            return []

        url      = str(self._helpers.analyzeRequest(
                       base_request_response).getUrl())
        findings = scan_body_for_secrets(body_str, url)
        if not findings:
            return []

        new_findings = []
        with _GLOBAL_SEEN_LOCK:
            for f in findings:
                key = (f.name, f.url, f.matched_value[:80])
                if key not in _GLOBAL_SEEN:
                    _GLOBAL_SEEN.add(key)
                    f.http_message = base_request_response
                    new_findings.append(f)

        if not new_findings:
            return []

        nf = new_findings
        SwingUtilities.invokeLater(
            _RunnableWrapper(lambda: self._tab.add_findings(nf)))

        svc     = base_request_response.getHttpService()
        req_url = self._helpers.analyzeRequest(base_request_response).getUrl()
        return [HackLensIssue(
            http_service=svc, url=req_url,
            http_messages=[base_request_response], finding=f)
            for f in new_findings]

    def doActiveScan(self, base_request_response, insertion_point):
        return []

    def consolidateDuplicateIssues(self, existing, new):
        if (existing.getIssueName() == new.getIssueName() and
                str(existing.getUrl()) == str(new.getUrl())):
            return -1
        return 0


# ============================================================
#  JYTHON RUNNABLE WRAPPER
# ============================================================
class _RunnableWrapper(Runnable):
    def __init__(self, fn):
        self._fn = fn
    def run(self):
        self._fn()
