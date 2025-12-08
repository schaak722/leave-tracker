# Leave Tracker – Architecture

This document describes the internal architecture of the Leave Tracker application:
how the main components fit together, where key logic lives, and how data flows
through the system.

It is aimed at developers working on the codebase.

---

## 1. High-Level Overview

Leave Tracker is a monolithic Flask web application with:

- **Flask** as the web framework (single `app.py` entry point)
- **SQLAlchemy** ORM for data access
- **PostgreSQL** (Neon) as the database
- **Bootstrap 5 + custom CSS** for UI
- **Server-side rendered** HTML via Jinja templates
- **Simple SMTP-based email** for notifications
- **Role-based access control** handled in `before_request`

There are **no background workers** or separate services. All business logic runs synchronously in the web app process.

---

## 2. Application Layers

### 2.1 Web / Routing Layer

All routes are defined in `app.py`. Key route categories:

- **Auth**
  - `GET /login` – login form
  - `POST /login` – authenticate user (username + password)
  - `GET /logout` – clear session

- **Calendar**
  - `GET /` – redirect to `/calendar/<year>` for the current year
  - `GET /calendar/<int:year>` – main calendar view (employees vs. days)
  - `POST /update_cell` – AJAX endpoint to toggle F/H/blank leave for a specific employee/date (admin/manager only)

- **Employee Views**
  - `GET /employee/<int:employee_id>/<int:year>` – per-employee yearly summary
  - `GET, POST /leave/request` – leave request form + validation + persistence

- **Admin / Manager**
  - `GET, POST /admin/users` – manage users
  - `POST /admin/users/<int:user_id>/update` – update existing user
  - `GET, POST /admin/employees` – manage employees
  - `GET /admin/leave_requests` – list leave requests (filter by status)
  - `POST /admin/leave_requests/<int:request_id>/decision` – approve/reject a leave request

Templates in `templates/` map roughly 1:1 with these route groups (`calendar.html`, `request_leave.html`, `manage_users.html`, `manage_employees.html`, etc.).

---

## 3. Authentication & Roles

### 3.1 Session & Current User

- User identity is stored in `session["user_id"]`.
- `@app.before_request`:
  - Loads the `User` from the DB.
  - Attaches it to `g.user`.
  - Normalises `user.role` to lower-case (`"admin"`, `"manager"`, `"employee"`).
  - Sets convenience flags:
    - `g.is_admin`
    - `g.is_manager`
    - `g.is_employee`

These flags are used in:

- Routes (e.g. guards like `if not g.is_admin: redirect(...)`)
- Templates (e.g. show/hide nav items, summary grid vs. cards)

### 3.2 Role Capabilities (Summary)

- **Employee**
  - Can view own calendar summary and request leave.
  - Cannot modify calendar cells.
  - Cannot access `/admin/*` routes.

- **Manager**
  - Can view all employees’ calendar and summary grid.
  - Can approve/reject leave requests.
  - Can edit leave cells via `/update_cell`.

- **Admin**
  - All manager capabilities plus:
  - Manage users (`/admin/users`).
  - Manage employees (`/admin/employees`).
  - Manage entitlements (where implemented).

---

## 4. Data Model

All models are defined in `app.py` using SQLAlchemy ORM.

### 4.1 Core Entities

- `Employee`
  - `id: int`
  - `name: str`
  - `birthday: date | None`
  - Relationships:
    - `entitlements` – list of `Entitlement`
    - `leave_entries` – list of `LeaveEntry`

- `User`
  - `id: int`
  - `username: str` (login + email for notifications)
  - `password_hash: str`
  - `role: str` – `"admin"`, `"manager"`, `"employee"`
  - `active: bool`
  - `employee_id: int | None` – foreign key to `Employee`
  - Methods:
    - `set_password(password)`
    - `check_password(password)`

- `Entitlement`
  - `id: int`
  - `employee_id: int`
  - `year: int`
  - `days: float` – annual leave entitlement

- `LeaveEntry`
  - Represents **final booked leave** on the calendar.
  - `id: int`
  - `employee_id: int`
  - `date: date`
  - `code: str` – `"F"` (full day) or `"H"` (half day)
  - `value: float` – `1.0` (full) or `0.5` (half)

- `LeaveRequest`
  - Represents a **requested** leave range (pending/approved/rejected).
  - `id: int`
  - `employee_id: int`
  - `start_date: date`
  - `end_date: date`
  - `code: str` – `"F"` or `"H"`
  - `status: str` – `"pending"`, `"approved"`, `"rejected"`
  - `requested_by_id: int` – `User` who made the request
  - `decision_by_id: int | None` – manager/admin who decided
  - `decision_at: datetime | None`
  - `manager_comment: str | None`

### 4.2 Public Holidays

- Defined in `public_holidays.py`:
  - `PUBLIC_HOLIDAYS` – list of holiday dates.
  - `iterate_working_days(start, end)` – generator used to:
    - Validate leave requests.
    - Create `LeaveEntry` records only on working days.

---

## 5. Main Business Flows

### 5.1 Leave Request (Employee)

1. Employee opens **Request Leave** page.
2. Fills in one or more ranges (start, end, half/full).
3. Server-side validation:
   - No weekends.
   - No public holidays.
   - No overlapping with existing `LeaveEntry`s for that employee.
4. On success:
   - One or more `LeaveRequest` rows are created (one per range).
   - Email notification is sent to all **active managers** (not admins).
5. Employee sees their request in the “Your requests” table.

### 5.2 Leave Approval (Manager/Admin)

1. Manager/admin opens **Leave requests** admin page.
2. For each pending `LeaveRequest`, they can **Approve** or **Reject**.
3. On approval:
   - `LeaveRequest.status` set to `"approved"`.
   - For each working day in `[start_date, end_date]`:
     - Check if `LeaveEntry` already exists for that employee/date.
     - If not, create a `LeaveEntry` with code/value based on `"F"`/`"H"`.
4. On rejection:
   - Only `LeaveRequest.status` is updated to `"rejected"`.
5. In both cases:
   - The employee receives an email decision notification.

### 5.3 Calendar Cell Editing (Admin/Manager)

- Allowed only for **admins/managers** via `/update_cell` (AJAX).
- Clicking a cell cycles:
  - `""` → `"F"` → `"H"` → `""`.
- The endpoint:
  - Validates role.
  - Inserts/updates/deletes `LeaveEntry` for the given employee/date.
  - Returns JSON `{success: true}` or an error.

---

## 6. Templates & UI Structure

### 6.1 Base Layout

- `templates/base.html`:
  - Includes Bootstrap, main CSS (`static/styles.css`), JS bundle.
  - Defines top navigation:
    - Left: logo (company-based).
    - Right: user dropdown (entries vary by role).
  - Defines footer with product/company info.
  - Wraps `{% block content %}` for all pages.

### 6.2 Key Templates

- `calendar.html`
  - Main yearly calendar view.
  - Uses `month_data` (precomputed in the view) to render 12 month blocks.
  - Employee names listed per row; days as columns.
  - Cells annotated with weekend/holiday/birthday information and leave `code`.
  - Employee view:
    - Shows three summary cards (Leave Days, Taken, Remaining).
    - Highlights the logged-in employee’s row via CSS class.

- `request_leave.html`
  - Shows employee’s leave summary for the year.
  - Multi-range leave request form.
  - Table of “Your requests”.

- `manage_users.html`
  - Create new user section.
  - Existing users table (role, active, linked employee, password).
  - Email/username is editable.

- `manage_employees.html`
  - Create/edit employees.
  - Basic data only (name, birthday, etc.).

- `admin_leave_requests.html` (or similarly named)
  - List of leave requests (filterable by status).
  - Approve/reject actions.

Email templates live under `templates/email/` and are rendered for the notification flows.

---

## 7. Configuration & Environments

Configuration is split between:

- `config.py` – Python module loaded by `app.py`.
- Environment variables (on Koyeb or locally).

Key settings:

- `DATABASE_URL` – Postgres connection string (Neon).
- `SECRET_KEY` – Flask session & CSRF secret.
- `ADMIN_USERNAME`, `ADMIN_PASSWORD` – used for initial admin bootstrap (if present).
- Email:
  - `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`
  - `MAIL_USERNAME`, `MAIL_PASSWORD`
  - `MAIL_DEFAULT_SENDER`
- Branding (optional / future):
  - `PRODUCT_NAME`, `COMPANY_NAME`, `COMPANY_URL`, `COMPANY_LOGO`, `SUPPORT_EMAIL`

The app uses `SQLALCHEMY_ENGINE_OPTIONS` to handle Neon’s idle connection behaviour:
e.g. `pool_pre_ping`, `pool_recycle`.

---

## 8. Extension Points / Future Work

- **White-labeling**
  - Move branding (names, logo, colours) into config and/or per-client DB records.
  - Use CSS variables for theming.

- **Multi-tenant**
  - Add `Client`/`Tenant` model.
  - Resolve `g.client` by `request.host`.
  - Inject client-specific branding and possibly SMTP settings.

- **Testing**
  - Introduce `pytest` for:
    - Public holiday utilities.
    - Leave validation logic.
    - Key route permissions.

- **Mobile UI**
  - Improve responsiveness of calendar and admin tables.
  - Possibly add a simplified employee mobile calendar.

This architecture is intentionally simple and monolithic, which keeps deployment
and development straightforward while still allowing incremental evolution into
a more white-label or multi-tenant solution if needed.
