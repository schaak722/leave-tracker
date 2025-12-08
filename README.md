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
