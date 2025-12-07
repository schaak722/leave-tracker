import os

# Secret key for sessions
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key-to-something-random")

# Admin login credentials
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "change-me")

# Outgoing mail settings (used for leave request notifications)
MAIL_SERVER = os.environ.get("MAIL_SERVER")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")

# Always send from the shared info@ address by default
MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "info@keepmeposted.com.mt")
