# Leave Tracker

Leave Tracker is an internal web application for managing employee leave.

It provides:

- A year calendar view with employee rows and day columns
- Role-based access for **Admins**, **Managers** and **Employees**
- Leave entitlements and remaining days tracking
- Leave requests and approvals (with email notifications)
- Public holidays and weekend handling
- Hosted on **Koyeb** with a **Neon PostgreSQL** backend

---

## Tech Stack

- **Backend:** Python, Flask
- **Database:** PostgreSQL (Neon) via SQLAlchemy
- **Frontend:** HTML, Jinja2, Bootstrap 5, custom CSS
- **Auth:** Simple username/password with hashed passwords
- **Hosting:** Koyeb (auto-deploy from GitHub)
- **Email:** SMTP (e.g. Gmail / Workspace / other provider)

---

## Core Concepts & Roles

### Models

Key SQLAlchemy models (defined in `app.py`):

- `Employee`
  - `id`, `name`, `birthday`
  - has many `Entitlement` and `LeaveEntry`
- `User`
  - `id`, `username`, `password_hash`, `role`, `active`, `employee_id`
  - `role`: `"admin"`, `"manager"`, `"employee"`
- `Entitlement`
  - `id`, `employee_id`, `year`, `days`
- `LeaveEntry`
  - Final, approved leave entries booked onto the calendar
  - `employee_id`, `date`, `code` (`"F"` full-day, `"H"` half-day), `value` (`1.0` or `0.5`)
- `LeaveRequest`
  - Requested leave ranges (for approval/rejection)
  - Approved requests generate one or more `LeaveEntry` records

### Roles

- **Employee**
  - Sees own summary cards (Leave Days, Taken, Remaining)
  - Can request leave
  - Cannot edit calendar cells
  - Sees their own row on the calendar, highlighted
- **Manager**
  - Can approve/reject leave requests
  - Can edit calendar cells
  - Sees summary grid for all employees
  - Gets email notifications when employees request leave
- **Admin**
  - Full access:
    - Manage users
    - Manage employees
    - Manage entitlements
    - Approve/reject leave
    - Edit calendar cells
  - Also sees all manager functionality

---

## Public Holidays

Public holidays are defined in `public_holidays.py`:

- `PUBLIC_HOLIDAYS` – list of holiday dates
- Helper functions:
  - `get_public_holiday_dates()`
  - `is_public_holiday(date)`
  - `iterate_working_days(start, end)` – skips weekends & holidays

These are used for validation when requesting leave and in the calendar display.

---

## Email Notifications

The app can send email notifications:

- When an employee **submits** a leave request:
  - Notifies **managers only** (not admins) by email
- When a manager **approves/rejects** a leave request:
  - Notifies the **employee** by email

Emails are sent via SMTP using configuration from environment variables (see below).  
If email is not configured, the app logs a warning and continues without failing.

---

## Getting Started (Local Development)

### 1. Prerequisites

- Python `3.10+` (Koyeb logs show `3.12` in use)
- PostgreSQL database (local or Neon)
- `git` and a GitHub repo (for deployment to Koyeb)

### 2. Clone the repo

```bash
git clone <your-repo-url>.git
cd <your-repo-folder>

**Create and activate a virtual environment**
python -m venv venv
source venv/bin/activate      # macOS / Linux
# or
venv\Scripts\activate         # Windows

**Install dependencies**
pip install -r requirements.txt

**Configure environment variables**
Create a .env file for local development (or set these in your shell):

# Core app config
FLASK_ENV=development
SECRET_KEY=change-this-in-production

# Database (example for Neon / local Postgres)
DATABASE_URL=postgresql+psycopg2://user:password@host:port/dbname

# Initial admin user (used if you have a bootstrapping step)
ADMIN_USERNAME=admin@example.com
ADMIN_PASSWORD=changeme

# SMTP / Email (optional but recommended)
MAIL_SERVER=smtp.example.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=leave-notify@example.com
MAIL_PASSWORD=your_smtp_password
MAIL_DEFAULT_SENDER=leave-notify@example.com

# Branding / white-label (optional, if configured in app.py/config.py)
PRODUCT_NAME=Leave Tracker
COMPANY_NAME=Keepmeposted
COMPANY_URL=https://keepmeposted.com.mt
COMPANY_LOGO=kmp_logo.png
SUPPORT_EMAIL=info@example.com


For local development you can also use a .flaskenv and python-dotenv if you prefer.

**Database setup**
How you create the tables depends on how you’ve wired the app:
If you’re using db.create_all() on startup:
Ensure DATABASE_URL is set and run the app once; tables will be created.
If you have a migration / helper script (e.g. run_migration.py or Alembic):
Run the appropriate command, e.g.:
python run_migration.py
# or
flask db upgrade

Check app.py / project scripts for the actual mechanism in use.

**Run the app locally**
Typically:
flask run
# or
python app.py

Then open:
http://127.0.0.1:5000 (or whatever port is printed in the console)

**Deployment (Koyeb + Neon)**

**Push to GitHub**
Commit your changes and push to your GitHub repo:

git add .
git commit -m "Initial Leave Tracker setup"
git push origin main

**Set up Neon (PostgreSQL)**
Create a Neon Postgres project.
Create a database (e.g. leave_tracker).
Get the connection string, e.g.:
postgresql://user:password@host/dbname?sslmode=require

Use this as your DATABASE_URL on Koyeb (with +psycopg2 if needed by SQLAlchemy).

**Create a Koyeb service**
New service → “Deploy from GitHub”
Select your repo and branch
Set build & run according to your app.py (e.g. using gunicorn)

**Set environment variables on Koyeb**
Define at least:
DATABASE_URL
SECRET_KEY
ADMIN_USERNAME, ADMIN_PASSWORD
MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS, MAIL_USERNAME, MAIL_PASSWORD, MAIL_DEFAULT_SENDER
Optional branding: PRODUCT_NAME, COMPANY_NAME, COMPANY_URL, COMPANY_LOGO, SUPPORT_EMAIL
Koyeb will redeploy automatically when you push to GitHub.

**Roles & Access Summary**
Admin
Access to manage users, employees, entitlements
View & decide on all leave requests
Edit calendar cells for any employee

Manager
Can approve/reject leave requests
Can edit calendar leave for employees
Sees all employees in the summary grid
Receives email notifications on new leave requests

Employee
Sees personal summary cards:
Leave Days
Taken
Remaining
Can submit leave requests
Sees own row highlighted in the calendar
Cannot edit calendar or access admin pages

**White-label & Theming (Future Work)**
The codebase can be adapted to white-label scenarios:

Branding via config:
PRODUCT_NAME, COMPANY_NAME, COMPANY_URL, COMPANY_LOGO

Colours via CSS variables:
E.g. --lt-primary, --lt-success, etc. set from config / template
Per-client deployments can each have their own env vars and logo in static/.

**Contributing / Working On This Project**
Use feature branches or work directly on main (for internal use).
Keep changes scoped:
e.g. “navbar dropdown”, “email notifications”, “leave request UI”
When in doubt, update README.md and in-code comments to reflect new behaviour.

**License**
Internal / private use. Decide and add a license if you intend to distribute this more broadly.


