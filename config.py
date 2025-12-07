import os

# Secret key for sessions
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key-to-something-random")

# Admin login credentials
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "change-me")

# Outgoing mail settings (used for leave request notifications)
MAIL_SERVER = os.environ.get("MAIL_SERVER")

# Handle empty MAIL_PORT gracefully (e.g. MAIL_PORT="" in env)
_mail_port_raw = os.environ.get("MAIL_PORT")
if _mail_port_raw and _mail_port_raw.strip():
    MAIL_PORT = int(_mail_port_raw)
else:
    MAIL_PORT = 587

_mail_use_tls_raw = os.environ.get("MAIL_USE_TLS")
if _mail_use_tls_raw and _mail_use_tls_raw.strip():
    MAIL_USE_TLS = _mail_use_tls_raw.lower() == "true"
else:
    MAIL_USE_TLS = True

MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")

# Always send from the shared info@ address by default
MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "info@keepmeposted.com.mt")

