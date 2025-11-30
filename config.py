import os

# Secret key for sessions
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key-to-something-random")

# Admin login credentials
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "change-me")

