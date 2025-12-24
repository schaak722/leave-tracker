from datetime import datetime, date, timedelta
import calendar
import os
from collections import defaultdict

from sqlalchemy import and_, or_

import smtplib
from email.message import EmailMessage

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, jsonify, abort, flash
)

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

import config          # SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD
import public_holidays # PUBLIC_HOLIDAYS dict

# ---------------------------
# App & DB config
# ---------------------------

app = Flask(__name__)

# Load from config.py
app.config["SECRET_KEY"] = config.SECRET_KEY

# Optional email settings (can be left unset in development)
app.config["MAIL_SERVER"] = config.MAIL_SERVER
app.config["MAIL_PORT"] = config.MAIL_PORT
app.config["MAIL_USE_TLS"] = config.MAIL_USE_TLS
app.config["MAIL_USERNAME"] = config.MAIL_USERNAME
app.config["MAIL_PASSWORD"] = config.MAIL_PASSWORD
app.config["MAIL_DEFAULT_SENDER"] = config.MAIL_DEFAULT_SENDER

# Prefer DATABASE_URL (Postgres in production), fall back to SQLite locally
database_url = os.environ.get("DATABASE_URL")

if not database_url:
    # Local development fallback: SQLite file next to app.py
    default_db_path = os.path.join(os.path.dirname(__file__), "leave_calendar.db")
    database_url = f"sqlite:///{default_db_path}"

# Optional: normalise old postgres:// URLs, just in case
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# IMPORTANT: make the DB pool resilient to idle timeouts
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,   # check connections before using them
    "pool_recycle": 300,     # recycle connections every 5 minutes
    # you *can* tweak pool_size/max_overflow if needed, but defaults are fine
}

db = SQLAlchemy(app)

def send_email(subject, recipients, body_text, body_html=None, reply_to=None):
    """Best-effort email sender used for leave request notifications."""
    server_host = app.config.get("MAIL_SERVER")
    server_port = app.config.get("MAIL_PORT", 587)
    use_tls = app.config.get("MAIL_USE_TLS", True)
    username = app.config.get("MAIL_USERNAME")
    password = app.config.get("MAIL_PASSWORD")
    sender = app.config.get("MAIL_DEFAULT_SENDER") or username

    # If email is not configured, quietly skip
    if not server_host or not username or not password or not recipients:
        app.logger.warning("Email not configured or missing recipients; skipping send_email()")
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    if reply_to:
        msg["Reply-To"] = reply_to

    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    try:
        with smtplib.SMTP(server_host, server_port) as server:
            if use_tls:
                server.starttls()
            server.login(username, password)
            server.send_message(msg)
    except Exception as e:
        app.logger.exception("Failed to send email: %s", e)

# Admin login from config.py (used only for bootstrapping the first admin user)
ADMIN_USERNAME = config.ADMIN_USERNAME
ADMIN_PASSWORD = config.ADMIN_PASSWORD

def ensure_admin_user():
    """
    Ensure DB tables exist and that there is at least one admin user.
    The first admin is bootstrapped from ADMIN_USERNAME / ADMIN_PASSWORD.
    """
    with app.app_context():
        db.create_all()

        admin_exists = User.query.filter_by(role="admin").first()
        if not admin_exists:
            username = ADMIN_USERNAME or "admin"
            password = ADMIN_PASSWORD or "change-me"

            user = User(
                username=username,
                role="admin",
                active=True,
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

# ---------------------------
# Models
# ---------------------------

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Legacy full-name field kept as canonical display + uniqueness across app
    name = db.Column(db.String(100), unique=True, nullable=False)

    # New split fields (nullable for backwards compatibility)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)

    # Metadata
    department = db.Column(db.String(100), nullable=True)

    # Role: employee | manager | admin
    role = db.Column(db.String(20), nullable=False, default="employee")

    active = db.Column(db.Boolean, default=True)
    birthday = db.Column(db.Date, nullable=True)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)

    # Reporting manager (another Employee)
    reporting_manager_id = db.Column(
        db.Integer,
        db.ForeignKey("employee.id"),
        nullable=True,
    )
    reporting_manager = db.relationship(
        "Employee",
        remote_side=[id],
        backref="direct_reports",
    )

    def __repr__(self):
        return f"<Employee {self.name}>"


class Entitlement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(
        db.Integer, db.ForeignKey("employee.id"), nullable=False
    )
    year = db.Column(db.Integer, nullable=False)
    days = db.Column(db.Float, nullable=False)

    employee = db.relationship("Employee", backref="entitlements")

    def __repr__(self):
        return f"<Entitlement {self.employee.name} {self.year}: {self.days}>"


class LeaveEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(
        db.Integer, db.ForeignKey("employee.id"), nullable=False
    )
    date = db.Column(db.Date, nullable=False)
    code = db.Column(db.String(1), nullable=False)   # "F" or "H"
    value = db.Column(db.Float, nullable=False)      # 1.0 or 0.5

    employee = db.relationship("Employee", backref="leave_entries")

    __table_args__ = (
        db.UniqueConstraint("employee_id", "date", name="uq_employee_date"),
    )

    def __repr__(self):
        return f"<LeaveEntry {self.employee.name} {self.date} {self.code}>"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    # Roles: "admin", "manager", "employee"
    # Existing "user" values will be treated as "employee" for compatibility.
    role = db.Column(db.String(20), default="employee")
    active = db.Column(db.Boolean, default=True)

    # Optional link to an Employee record (for people whose leave you track)
    employee_id = db.Column(db.Integer, db.ForeignKey("employee.id"), nullable=True)
    employee = db.relationship("Employee", backref="users")

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    employee_id = db.Column(db.Integer, db.ForeignKey("employee.id"), nullable=False)
    employee = db.relationship("Employee", backref="leave_requests")

    requested_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    requested_by = db.relationship("User", foreign_keys=[requested_by_id])

    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    code = db.Column(db.String(1), nullable=False)  # "F" or "H"
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    status = db.Column(db.String(20), default="pending", nullable=False)
    # "pending", "approved", "rejected", "cancelled"

    # This maps to the existing DB column "decision_comment" which we
    # originally used for the employee's note.
    employee_comment = db.Column("decision_comment", db.Text)

    # New column for manager's decision comment (this will create a new
    # nullable column manager_comment in the DB).
    manager_comment = db.Column(db.Text)

    decision_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    decision_by = db.relationship("User", foreign_keys=[decision_by_id])
    decision_at = db.Column(db.DateTime)

    def __repr__(self):
        return f"<LeaveRequest {self.employee.name} {self.start_date}–{self.end_date} {self.status}>"

ensure_admin_user()

# ---------------------------
# Helpers
# ---------------------------

@app.before_request
def load_logged_in_user():
    g.user = None
    g.is_admin = False
    g.is_manager = False
    g.is_employee = False

    user_id = session.get("user_id")
    if user_id is not None:
        user = User.query.get(user_id)
        if user and user.active:
            g.user = user

            # Normalise role to handle "Employee", "USER", etc.
            role = (user.role or "employee").strip().lower()
            if role == "user":
                role = "employee"

            g.is_admin = (role == "admin")
            g.is_manager = (role == "manager")
            g.is_employee = (role == "employee")

def get_available_years(current_year: int, selected_year: int):
    """
    Return a sorted list of years that:
      - have entitlements or entries, OR
      - are the current calendar year, OR
      - are the currently selected year in the UI.

    This guarantees that:
      - the current year is always in the dropdown, and
      - the selected year never disappears when you switch.
    """
    years = set()

    # Years that have entitlement records
    ent_years = db.session.query(Entitlement.year).distinct().all()
    for y, in ent_years:
        years.add(y)

    # Years that have leave entries
    entry_years = db.session.query(
        db.extract("year", LeaveEntry.date)
    ).distinct().all()
    for y in entry_years:
        years.add(int(y[0]))

    # Always include current calendar year and currently selected year
    years.add(current_year)
    years.add(selected_year)

    return sorted(years)

def get_public_holiday_dates(year: int):
    """
    Returns a set of ISO date strings 'YYYY-MM-DD' for the given year.
    """
    dates = set()
    for ds in public_holidays.PUBLIC_HOLIDAYS.get(year, []):
        try:
            d = datetime.strptime(ds, "%Y-%m-%d").date()
            dates.add(d.isoformat())
        except ValueError:
            # Ignore invalid entries
            continue
    return dates

def is_public_holiday(d: date) -> bool:
    """
    Return True if this date is in the PUBLIC_HOLIDAYS dict.
    """
    dates_for_year = public_holidays.PUBLIC_HOLIDAYS.get(d.year, [])
    # PUBLIC_HOLIDAYS uses "YYYY-MM-DD" strings
    return d.isoformat() in dates_for_year

def iterate_working_days(start_date: date, end_date: date):
    """
    Yield all working days (Mon–Fri) between start_date and end_date,
    skipping weekends and public holidays.
    """
    current = start_date
    while current <= end_date:
        # weekday(): 0=Mon, 6=Sun
        if current.weekday() < 5 and not is_public_holiday(current):
            yield current
        current += timedelta(days=1)

def compute_year_summary(year: int):
    """
    Return:
      - employees shown on the calendar for this year (based on employment date overlap),
      - per_employee list with entitlement/taken/remaining,
      - cell_codes mapping "employeeId_YYYY-MM-DD" -> code ("F"/"H").
    """
    year_start = date(year, 1, 1)
    year_end = date(year, 12, 31)

    # Employment overlap:
    #  - start_date is null OR start_date <= year_end
    #  - end_date is null OR end_date >= year_start
    overlaps_year = and_(
        or_(Employee.start_date.is_(None), Employee.start_date <= year_end),
        or_(Employee.end_date.is_(None), Employee.end_date >= year_start),
    )

    # Employees who have an entitlement for this year AND overlap the year
    employees = (
        db.session.query(Employee)
        .join(Entitlement, Employee.id == Entitlement.employee_id)
        .filter(Entitlement.year == year)
        .filter(overlaps_year)
        .order_by(Employee.name)
        .all()
    )

    entitlements = Entitlement.query.filter_by(year=year).all()

    entries = (
        LeaveEntry.query
        .filter(db.extract("year", LeaveEntry.date) == year)
        .all()
    )

    # Ensure anyone with leave entries in this year remains visible even if entitlement is missing
    entry_employee_ids = {e.employee_id for e in entries}
    if entry_employee_ids:
        employees_with_entries = (
            Employee.query
            .filter(Employee.id.in_(entry_employee_ids))
            .order_by(Employee.name)
            .all()
        )
        # Merge + de-duplicate
        employees_by_id = {e.id: e for e in employees}
        for e in employees_with_entries:
            employees_by_id[e.id] = e
        employees = sorted(employees_by_id.values(), key=lambda e: (e.name or "").lower())

    entitlement_map = {e.employee_id: e.days for e in entitlements}

    taken_map = defaultdict(float)
    for entry in entries:
        taken_map[entry.employee_id] += entry.value

    per_employee = []
    for emp in employees:
        entitlement = entitlement_map.get(emp.id, 0.0)
        taken = taken_map.get(emp.id, 0.0)
        remaining = entitlement - taken
        per_employee.append({
            "employee": emp,
            "entitlement": entitlement,
            "taken": taken,
            "remaining": remaining
        })

    # For fast lookup in templates
    cell_codes = {}
    for entry in entries:
        key = f"{entry.employee_id}_{entry.date.isoformat()}"
        cell_codes[key] = entry.code

    return employees, per_employee, cell_codes

def compute_employee_year_summary(employee_id: int, year: int):
    """
    Return entitlement, taken, remaining for a single employee in a given year.
    """
    entitlement = (
        Entitlement.query
        .filter_by(employee_id=employee_id, year=year)
        .first()
    )
    entitlement_days = entitlement.days if entitlement else 0.0

    entries = (
        LeaveEntry.query
        .filter(LeaveEntry.employee_id == employee_id)
        .filter(db.extract("year", LeaveEntry.date) == year)
        .all()
    )
    taken = sum(e.value for e in entries)
    remaining = entitlement_days - taken

    return entitlement_days, taken, remaining

def parse_date_input(date_str: str):
    """
    Parse dates from common UI formats.
    Primary format for this change: DD/MM/YY
    Also accepts: DD/MM/YYYY, DD-MM-YY, DD-MM-YYYY, YYYY-MM-DD
    Returns a date or None.
    """
    date_str = (date_str or "").strip()
    if not date_str:
        return None

    formats = ["%d/%m/%y", "%d/%m/%Y", "%d-%m-%y", "%d-%m-%Y", "%Y-%m-%d"]
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt).date()
        except ValueError:
            continue

    return None
    
def parse_birthday(birthday_str: str):
    """
    Backwards compatible birthday parsing.
    Primary format: DD/MM/YY
    Also accepts: YYYY-MM-DD, DD/MM/YYYY, DD-MM-YYYY, etc.
    """
    return parse_date_input(birthday_str)

    birthday_str = (birthday_str or "").strip()
    if not birthday_str:
        return None

    formats = ["%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"]
    for fmt in formats:
        try:
            return datetime.strptime(birthday_str, fmt).date()
        except ValueError:
            continue

    return None

def get_approvers_for_employee(employee: Employee):
    """
    Return a list of User objects who should be notified / approve leave
    for this employee.

    Phase 1 logic:
    - If employee.reporting_manager_id is set and that person has an active
      manager User, return just that user.
    - Otherwise fall back to all active managers (existing behaviour).
    """
    if not employee:
        return []

    approvers = []

    # 1) Explicit reporting manager, if configured
    if employee.reporting_manager_id:
        manager_user = (
            User.query.filter_by(
                employee_id=employee.reporting_manager_id,
                role="manager",
                active=True,
            )
            .first()
        )
        if manager_user:
            approvers.append(manager_user)

    # 2) Fallback: all active managers (current behaviour)
    if not approvers:
        approvers = (
            User.query.filter_by(role="manager", active=True)
            .order_by(User.username)
            .all()
        )

    return approvers

# ---------------------------
# Routes
# ---------------------------

@app.route("/initdb")
def initdb():
    """
    Protected DB initialisation route.

    In production this is disabled by default so random people
    can't hit it. To enable temporarily, set ENABLE_INITDB=true
    in the environment, call this route once, then turn it off.
    """
    enable_initdb = os.environ.get("ENABLE_INITDB", "false").lower() == "true"
    if not enable_initdb:
        abort(404)

    db.create_all()
    return "Database initialised. You can now turn off ENABLE_INITDB."

@app.route("/")
def index():
    # Require login to see anything
    if not g.user:
        return redirect(url_for("login"))

    current_year = datetime.now().year
    return redirect(url_for("calendar_view", year=current_year))

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Admin/user login with simple per-session rate limiting:
    - After 5 failed attempts, lock further attempts for 10 minutes.
    """
    error = None
    username = ""

    # --- check for existing lockout ---
    lock_until_str = session.get("login_lock_until")
    locked = False

    if lock_until_str:
        try:
            lock_until = datetime.fromisoformat(lock_until_str)
            # Use UTC for consistency
            if datetime.utcnow() < lock_until:
                locked = True
            else:
                # Lockout expired, reset counters
                session.pop("login_lock_until", None)
                session.pop("login_attempts", None)
        except ValueError:
            # Bad data? Reset lock info.
            session.pop("login_lock_until", None)
            session.pop("login_attempts", None)

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password", "")

        # If locked, do not even check credentials
        if locked:
            error = "Too many failed login attempts. Please try again later."
            return render_template("login.html", error=error, username=username)

        # Look up user
        user = User.query.filter_by(username=username, active=True).first()

        if user and user.check_password(password):
            # Successful login
            session.clear()
            session["user_id"] = user.id
            session["is_admin"] = (user.role == "admin")
            # Clear any previous failure tracking
            session.pop("login_attempts", None)
            session.pop("login_lock_until", None)
            return redirect(url_for("index"))

        # Credentials invalid: increment attempt counter
        attempts = session.get("login_attempts", 0) + 1
        session["login_attempts"] = attempts

        if attempts >= 5:
            # Lock for 10 minutes
            lock_until = datetime.utcnow() + timedelta(minutes=10)
            session["login_lock_until"] = lock_until.isoformat()
            error = "Too many failed login attempts. Please try again later."
        else:
            error = "Invalid username or password."

        return render_template("login.html", error=error, username=username)

    # GET: show lockout message if still locked
    if locked:
        error = "Too many failed login attempts. Please try again later."

    # If user is already logged in, optionally redirect away from login page
    if g.user:
        return redirect(url_for("index"))

    return render_template("login.html", error=error, username=username)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/calendar/<int:year>")
def calendar_view(year):
    # Require login to view the calendar
    if not g.user:
        return redirect(url_for("login"))

    current_year = datetime.now().year
    years = get_available_years(current_year, year)

    employees, per_employee, cell_codes = compute_year_summary(year)

    # Build month data: name + list of days + weekday letters
    month_data = []
    weekday_letters_map = ["M", "T", "W", "T", "F", "S", "S"]

    for m in range(1, 13):
        _, days_in_month = calendar.monthrange(year, m)
        days = list(range(1, days_in_month + 1))
        weekday_letters = []
        for d in days:
            w = date(year, m, d).weekday()  # 0=Mon
            weekday_letters.append(weekday_letters_map[w])

        month_data.append({
            "month_number": m,
            "month_name": calendar.month_name[m],
            "days": days,
            "weekday_letters": weekday_letters,
        })

    public_holiday_dates = get_public_holiday_dates(year)

    return render_template(
        "calendar.html",
        year=year,
        years=years,
        employees=employees,
        per_employee=per_employee,
        month_data=month_data,
        cell_codes=cell_codes,
        public_holiday_dates=public_holiday_dates,
    )

@app.route("/employee/<int:employee_id>/<int:year>")
def employee_summary(employee_id, year):
    if not g.user:
        return redirect(url_for("login"))

    emp = Employee.query.get_or_404(employee_id)
    entries = (
        LeaveEntry.query
        .filter(LeaveEntry.employee_id == employee_id)
        .filter(db.extract("year", LeaveEntry.date) == year)
        .order_by(LeaveEntry.date)
        .all()
    )

    entitlement = (
        Entitlement.query
        .filter_by(employee_id=employee_id, year=year)
        .first()
    )
    entitlement_days = entitlement.days if entitlement else 0.0
    taken = sum(e.value for e in entries)
    remaining = entitlement_days - taken

    return render_template(
        "employee_summary.html",
        employee=emp,
        year=year,
        entries=entries,
        entitlement=entitlement_days,
        taken=taken,
        remaining=remaining,
    )

@app.route("/leave/request", methods=["GET", "POST"])
def request_leave():
    # Must be logged in
    if not g.user:
        return redirect(url_for("login"))

    # Require the user to be linked to an Employee
    employee = None
    if hasattr(g.user, "employee") and g.user.employee:
        employee = g.user.employee
    elif getattr(g.user, "employee_id", None):
        employee = Employee.query.get(g.user.employee_id)

    if not employee:
        # No employee record linked: we can't know whose leave to track
        error = "Your user account is not linked to an employee. Please contact an admin."
        return render_template(
            "request_leave.html",
            employee=None,
            year=None,
            entitlement=None,
            taken=None,
            remaining=None,
            requests=[],
            error=error,
            success=None,
        )

    error = None
    success = None
    current_year = datetime.now().year

    if request.method == "POST":
        # Multiple rows: each row has start_date, end_date, code
        start_list = [(s or "").strip() for s in request.form.getlist("start_date")]
        end_list = [(s or "").strip() for s in request.form.getlist("end_date")]
        code_list = [(c or "").strip().upper() for c in request.form.getlist("code")]
        comment = (request.form.get("comment") or "").strip()

        rows = []

        for idx, (start_str, end_str, code) in enumerate(
            zip(start_list, end_list, code_list), start=1
        ):
            # Skip completely empty rows
            if not start_str and not end_str and not code:
                continue

            # Basic validation
            if not start_str or not end_str or code not in ("F", "H"):
                error = (
                    "Please provide a start date, end date, and select full-day "
                    "or half-day for each row."
                )
                break

            try:
                start_date = datetime.strptime(start_str, "%Y-%m-%d").date()
                end_date = datetime.strptime(end_str, "%Y-%m-%d").date()
            except ValueError:
                error = "Invalid date format."
                break

            if end_date < start_date:
                error = "End date cannot be before start date."
                break

            # 1) Block weekends / public holidays anywhere in the selected range
            current = start_date
            while current <= end_date:
                if current.weekday() >= 5 or is_public_holiday(current):
                    error = "You cannot book weekends or public holidays"
                    break
                current += timedelta(days=1)

            if error:
                break

            # 2) Build list of working days (Mon–Fri excluding public holidays)
            working_days = list(iterate_working_days(start_date, end_date))
            if not working_days:
                error = "Selected range does not contain any working days you can book."
                break

            # 3) Check for existing leave entries on any of those working days
            existing = (
                LeaveEntry.query.filter(
                    LeaveEntry.employee_id == employee.id,
                    LeaveEntry.date.in_(working_days),
                )
                .first()
            )
            if existing:
                error = "You already have this day booked"
                break

            rows.append((start_date, end_date, code))

        if not error:
            if not rows:
                error = "Please add at least one date or range."
            else:
                # Create one pending LeaveRequest per valid row
                for (start_date, end_date, code) in rows:
                    lr = LeaveRequest(
                        employee_id=employee.id,
                        requested_by_id=g.user.id,
                        start_date=start_date,
                        end_date=end_date,
                        code=code,
                        status="pending",
                        employee_comment=comment or None,
                    )
                    db.session.add(lr)

                db.session.commit()

                # Email notification to relevant manager(s) about new leave request(s)
                try:
                    employee_user = g.user
                    # We already resolved employee above; ensure it's still valid
                    employee_email = getattr(employee_user, "username", None)

                    # Use helper: reporting manager if set, otherwise all active managers
                    approvers = get_approvers_for_employee(employee)
                    recipient_emails = [u.username for u in approvers if u.username]
                except Exception:
                    employee_email = None
                    recipient_emails = []

                if recipient_emails and employee and employee_email:
                    subject = f"[Leave Tracker] New leave request from {employee.name}"
                    leave_requests_url = url_for("list_leave_requests", _external=True)

                    text_body = render_template(
                        "email/new_leave_request_manager.txt",
                        employee=employee,
                        employee_email=employee_email,
                        leave_requests_url=leave_requests_url,
                    )
                    html_body = render_template(
                        "email/new_leave_request_manager.html",
                        employee=employee,
                        employee_email=employee_email,
                        leave_requests_url=leave_requests_url,
                    )

                    send_email(
                        subject=subject,
                        recipients=recipient_emails,
                        body_text=text_body,
                        body_html=html_body,
                        reply_to=employee_email,  # reply goes to employee
                    )

                if len(rows) == 1:
                    success = "Your leave request has been submitted."
                else:
                    success = f"Your {len(rows)} leave requests have been submitted."

    # Summary for the current year
    entitlement, taken, remaining = compute_employee_year_summary(
        employee.id,
        current_year,
    )

    # All requests for this employee, newest first
    requests = (
        LeaveRequest.query.filter_by(employee_id=employee.id)
        .order_by(LeaveRequest.created_at.desc())
        .all()
    )

    return render_template(
        "request_leave.html",
        employee=employee,
        year=current_year,
        entitlement=entitlement,
        taken=taken,
        remaining=remaining,
        requests=requests,
        error=error,
        success=success,
    )

@app.route("/admin/leave_requests", methods=["GET"])
def list_leave_requests():
    if not (g.is_admin or g.is_manager):
        return redirect(url_for("login"))

    # Filter: all by default, or ?status=pending / approved / rejected / all
    filter_status = request.args.get("status", "all")

    query = (
        LeaveRequest.query
        .join(Employee)
        .order_by(LeaveRequest.created_at.desc())
    )

    if filter_status != "all":
        query = query.filter(LeaveRequest.status == filter_status)

    requests = query.all()

    return render_template(
        "manage_leave_requests.html",
        requests=requests,
        filter_status=filter_status,
    )

@app.route("/admin/leave_requests/<int:request_id>/decision", methods=["POST"])
def decide_leave_request(request_id):
    if not (g.is_admin or g.is_manager):
        return redirect(url_for("login"))

    lr = LeaveRequest.query.get_or_404(request_id)

    # Only allow acting on pending requests
    if lr.status != "pending":
        return redirect(url_for("list_leave_requests", status="pending"))

    action = (request.form.get("action") or "").strip()
    manager_comment = (request.form.get("manager_comment") or "").strip()

    if action not in ("approve", "reject"):
        return redirect(url_for("list_leave_requests", status="pending"))

    lr.decision_by_id = g.user.id
    lr.decision_at = datetime.utcnow()
    lr.manager_comment = manager_comment or None

    if action == "approve":
        lr.status = "approved"

        # Create LeaveEntry rows for each working day in the range
        for d in iterate_working_days(lr.start_date, lr.end_date):
            # Skip if an entry already exists for this employee/date
            existing = (
                LeaveEntry.query
                .filter_by(employee_id=lr.employee_id, date=d)
                .first()
            )
            if existing:
                continue

            value = 1.0 if lr.code == "F" else 0.5
            entry = LeaveEntry(
                employee_id=lr.employee_id,
                date=d,
                code=lr.code,
                value=value,
            )
            db.session.add(entry)

    elif action == "reject":
        lr.status = "rejected"

    db.session.commit()

    # Email notification to employee about decision
    try:
        employee = lr.employee
        employee_user = (
            User.query.filter_by(employee_id=employee.id, active=True).first()
            if employee
            else None
        )
        employee_email = (
            employee_user.username
            if employee_user and employee_user.username
            else None
        )

        manager_user = g.user
        manager_email = getattr(manager_user, "username", None)
        manager_name = (
            manager_user.username
            if manager_user and manager_user.username
            else "Your manager"
        )

        decision_word = "approved" if action == "approve" else "rejected"

        if employee_email and manager_email:
            subject = f"[Leave Tracker] Your leave request has been {decision_word}"
            calendar_url = url_for("index", _external=True)

            text_body = render_template(
                "email/leave_request_decision_employee.txt",
                employee=employee,
                manager_name=manager_name,
                decision=decision_word,
                calendar_url=calendar_url,
            )
            html_body = render_template(
                "email/leave_request_decision_employee.html",
                employee=employee,
                manager_name=manager_name,
                decision=decision_word,
                calendar_url=calendar_url,
            )

            send_email(
                subject=subject,
                recipients=[employee_email],
                body_text=text_body,
                body_html=html_body,
                reply_to=manager_email,  # replies go to the manager
            )
    except Exception as e:
        app.logger.exception("Failed to send decision email: %s", e)

    return redirect(url_for("list_leave_requests", status="pending"))

@app.route("/update_cell", methods=["POST"])
def update_cell():
    # Only admins or managers can edit calendar cells (F/H)
    if not (g.is_admin or g.is_manager):
        return jsonify({"success": False, "error": "Not authorised"}), 403

    data = request.get_json() or {}
    employee_id = int(data.get("employee_id", 0))
    code = (data.get("code") or "").strip().upper()
    date_str = data.get("date")

    if not employee_id or not date_str:
        return jsonify({"success": False, "error": "Missing data"}), 400

    if code not in ("F", "H", ""):
        return jsonify({"success": False, "error": "Invalid code"}), 400

    try:
        d = datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"success": False, "error": "Invalid date"}), 400

    # Do not allow setting F/H on weekends or public holidays
    public_holiday_dates = get_public_holiday_dates(d.year)
    if (d.weekday() >= 5 or d.isoformat() in public_holiday_dates) and code != "":
        return jsonify({
            "success": False,
            "error": "Cannot set leave on weekends or public holidays",
        }), 400

    entry = LeaveEntry.query.filter_by(employee_id=employee_id, date=d).first()

    # Blank = delete entry if it exists
    if code == "":
        if entry:
            db.session.delete(entry)
            db.session.commit()
        return jsonify({"success": True})

    # Determine value
    value = 1.0 if code == "F" else 0.5

    if not entry:
        entry = LeaveEntry(
            employee_id=employee_id,
            date=d,
            code=code,
            value=value,
        )
        db.session.add(entry)
    else:
        entry.code = code
        entry.value = value

    db.session.commit()
    return jsonify({"success": True})


# ---------------------------
# Admin: add / update entitlement (and birthday)
# ---------------------------

@app.route("/admin/add_employee", methods=["GET", "POST"], endpoint="add_employee")
def add_employee():
    """
    Add / update employee and entitlement for a year.
    Uses split name fields but keeps Employee.name as the canonical display field.
    """
    if not g.is_admin:
        return redirect(url_for("login"))

    if request.method == "POST":
        first_name = (request.form.get("first_name") or "").strip()
        last_name = (request.form.get("last_name") or "").strip()
        department = (request.form.get("department") or "").strip()

        full_name = f"{first_name} {last_name}".strip()

        year_str = (request.form.get("year") or "").strip()
        days_str = (request.form.get("entitlement_days") or "").strip()
        birthday_str = (request.form.get("birthday") or "").strip()

        if not first_name:
            flash("First name is required.", "warning")
            return redirect(url_for("add_employee"))

        if not last_name:
            flash("Last name is required.", "warning")
            return redirect(url_for("add_employee"))

        try:
            year = int(year_str)
            entitlement_days = float(days_str)
        except ValueError:
            flash("Invalid year or leave days.", "warning")
            return redirect(url_for("add_employee"))

        emp = Employee.query.filter_by(name=full_name).first()
        if not emp:
            emp = Employee(
                name=full_name,
                first_name=first_name,
                last_name=last_name,
                department=department if department else None,
                active=True
            )
            db.session.add(emp)
            db.session.flush()
        else:
            # Keep split fields in sync if employee already exists
            emp.first_name = first_name
            emp.last_name = last_name
            emp.department = department if department else None
            emp.name = full_name

        # Birthday (optional)
        if birthday_str:
            bday = parse_birthday(birthday_str)
            if not bday:
                flash("Invalid birthday date.", "warning")
                return redirect(url_for("add_employee"))
            emp.birthday = bday
        else:
            emp.birthday = None

        ent = Entitlement.query.filter_by(employee_id=emp.id, year=year).first()
        if ent:
            ent.days = entitlement_days
        else:
            db.session.add(Entitlement(employee_id=emp.id, year=year, days=entitlement_days))

        db.session.commit()
        flash("Employee and leave days saved.", "success")
        return redirect(url_for("manage_employees"))

    current_year = datetime.now().year
    return render_template(
        "base.html",
        content=f"""
        <h2>Add / Update Leave Days</h2>

        <form method='post' class='mt-3'>
            <div class='row'>
              <div class='col-md-6 mb-3'>
                <label class='form-label'>First name
                  <input type='text' name='first_name' class='form-control' required>
                </label>
              </div>
              <div class='col-md-6 mb-3'>
                <label class='form-label'>Last name
                  <input type='text' name='last_name' class='form-control' required>
                </label>
              </div>
            </div>

            <div class='mb-3'>
              <label class='form-label'>Department
                <input type='text' name='department' class='form-control'>
              </label>
            </div>

            <div class='mb-3'>
              <label class='form-label'>Birthday
                <input type='date' name='birthday' class='form-control'>
              </label>
            </div>

            <div class='mb-3'>
              <label class='form-label'>Year
                <input type='number' name='year' value='{current_year}' class='form-control' required>
              </label>
            </div>

            <div class='mb-3'>
              <label class='form-label'>Leave days
                <input type='number' step='0.5' name='entitlement_days' class='form-control' required>
              </label>
            </div>

            <div class='mt-3'>
              <a href='{url_for("manage_employees")}' class='btn btn-secondary me-2'>Back</a>
              <button type='submit' class='btn btn-primary'>Save</button>
            </div>
        </form>
        """,
    )
# ---------------------------
# Admin: manage employees (list / edit / delete)
# ---------------------------

@app.route("/admin/employees")
def manage_employees():
    if not g.is_admin:
        return redirect(url_for("login"))

    show_archived = (request.args.get("show_archived") or "").strip() in ("1", "true", "yes", "on")

    if show_archived:
        employees = (
            Employee.query
            .filter(Employee.active.is_(False))
            .order_by(Employee.name)
            .all()
        )
    else:
        employees = (
            Employee.query
            .filter(Employee.active.is_(True))
            .order_by(Employee.name)
            .all()
        )

    # Managers list for Create Employee modal
    manager_employees = (
        Employee.query
        .join(User, User.employee_id == Employee.id)
        .filter(User.active.is_(True), User.role == "manager")
        .order_by(Employee.name)
        .all()
    )

    return render_template(
        "manage_employees.html",
        employees=employees,
        show_archived=show_archived,
        manager_employees=manager_employees,
    )

@app.route("/admin/employees/create", methods=["POST"])
def create_employee_modal():
    if not g.is_admin:
        return redirect(url_for("login"))

    # Required (per your rule)
    first_name = (request.form.get("first_name") or "").strip()
    last_name = (request.form.get("last_name") or "").strip()
    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    # Optional employee fields
    birthday_str = (request.form.get("birthday") or "").strip()
    start_date_str = (request.form.get("start_date") or "").strip()
    end_date_str = (request.form.get("end_date") or "").strip()
    department = (request.form.get("department") or "").strip()
    reporting_manager_id_str = (request.form.get("reporting_manager_id") or "").strip()

    role = (request.form.get("role") or "employee").strip().lower()
    if role not in ("employee", "manager", "admin"):
        flash("Invalid role.", "danger")
        return redirect(url_for("manage_employees"))

    active = True if request.form.get("active") == "on" else False

    # Leave days (required unless admin)
    ent_year_str = (request.form.get("entitlement_year") or "").strip()
    ent_days_str = (request.form.get("entitlement_days") or "").strip()

    # Validation
    if not first_name or not last_name:
        flash("First name and last name are required.", "danger")
        return redirect(url_for("manage_employees"))

    if not email:
        flash("Email (username) is required.", "danger")
        return redirect(url_for("manage_employees"))

    if not password:
        flash("Password is required.", "danger")
        return redirect(url_for("manage_employees"))

    if password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("manage_employees"))

    if User.query.filter_by(username=email).first():
        flash("That email/username is already in use.", "danger")
        return redirect(url_for("manage_employees"))

    full_name = f"{first_name} {last_name}".strip()
    existing_emp = Employee.query.filter(Employee.name == full_name).first()
    if existing_emp:
        flash("An employee with that name already exists.", "danger")
        return redirect(url_for("manage_employees"))

    # Parse dates
    birthday = parse_birthday(birthday_str) if birthday_str else None
    if birthday_str and not birthday:
        flash("Invalid birthday date.", "danger")
        return redirect(url_for("manage_employees"))

    sd = parse_date_input(start_date_str) if start_date_str else None
    if start_date_str and not sd:
        flash("Invalid start date.", "danger")
        return redirect(url_for("manage_employees"))

    ed = parse_date_input(end_date_str) if end_date_str else None
    if end_date_str and not ed:
        flash("Invalid end date.", "danger")
        return redirect(url_for("manage_employees"))

    if sd and ed and ed < sd:
        flash("End date cannot be earlier than start date.", "danger")
        return redirect(url_for("manage_employees"))

    # Parse reporting manager (optional)
    reporting_manager_id = None
    if reporting_manager_id_str:
        try:
            reporting_manager_id = int(reporting_manager_id_str)
        except ValueError:
            reporting_manager_id = None

    # Leave days validation (non-admin only)
    entitlement_year = None
    entitlement_days = None
    if role != "admin":
        if not ent_year_str or not ent_days_str:
            flash("Leave days and year are required for Employees and Managers.", "danger")
            return redirect(url_for("manage_employees"))
        try:
            entitlement_year = int(ent_year_str)
            entitlement_days = float(ent_days_str)
        except ValueError:
            flash("Invalid leave days year or value.", "danger")
            return redirect(url_for("manage_employees"))

    # Create Employee
    emp = Employee(
        name=full_name,
        first_name=first_name,
        last_name=last_name,
        department=department if department else None,
        role=role,
        active=active,
        birthday=birthday,
        start_date=sd,
        end_date=ed,
        reporting_manager_id=reporting_manager_id,
    )
    db.session.add(emp)
    db.session.flush()  # ensures emp.id exists for user/entitlement

    # Create User (mandatory)
    user = User(
        username=email,
        role=role,
        active=active,
        employee_id=emp.id,
    )
    user.set_password(password)
    db.session.add(user)

    # Create Entitlement (non-admin only)
    if role != "admin":
        ent = Entitlement(employee_id=emp.id, year=entitlement_year, days=entitlement_days)
        db.session.add(ent)

    db.session.commit()
    flash("Employee created.", "success")
    return redirect(url_for("manage_employees"))

@app.route("/admin/employee/<int:employee_id>/edit", methods=["GET", "POST"])
def edit_employee(employee_id):
    if not g.is_admin:
        return redirect(url_for("login"))

    emp = Employee.query.get_or_404(employee_id)
    error = None

        # Linked login (for now we keep the User table, but manage it here)
    linked_user = User.query.filter_by(employee_id=emp.id).first()
    username_value = linked_user.username if linked_user else ""

    # Leave days editor: default to current year, or edit a specific year via ?edit_year=YYYY
    current_year = datetime.now().year

    edit_year = request.args.get("edit_year", "").strip()
    is_edit_mode = False
    entitlement_year_value = current_year
    entitlement_days_value = ""

    if edit_year:
        try:
            entitlement_year_value = int(edit_year)
            is_edit_mode = True
        except ValueError:
            entitlement_year_value = current_year
            is_edit_mode = False

    ent_for_year = (
        Entitlement.query
        .filter_by(employee_id=emp.id, year=entitlement_year_value)
        .first()
    )
    entitlement_days_value = ent_for_year.days if ent_for_year else ""
    # If someone tries to edit a year that doesn't exist, fall back to add mode
    if is_edit_mode and not ent_for_year:
        is_edit_mode = False
        entitlement_year_value = current_year
        ent_for_year = (
            Entitlement.query
            .filter_by(employee_id=emp.id, year=entitlement_year_value)
            .first()
        )
        entitlement_days_value = ent_for_year.days if ent_for_year else ""

    # Managers list (keep your existing behaviour for now)
    manager_employees = (
        Employee.query
        .join(User, User.employee_id == Employee.id)
        .filter(User.active.is_(True), User.role == "manager")
        .order_by(Employee.name)
        .all()
    )

    # Ensure current reporting manager (if any) is in the list
    if emp.reporting_manager and emp.reporting_manager not in manager_employees:
        manager_employees.append(emp.reporting_manager)

    if request.method == "POST":
        form_action = (request.form.get("form_action") or "").strip()

        # -------------------------
        # A) Save employee details
        # -------------------------
        if form_action == "employee_details":
            first_name = (request.form.get("first_name") or "").strip()
            last_name = (request.form.get("last_name") or "").strip()
            department = (request.form.get("department") or "").strip()
            email = (request.form.get("email") or "").strip()
            password = request.form.get("password") or ""
            confirm_password = request.form.get("confirm_password") or ""

            # New: role on Employee
            role = (request.form.get("role") or "employee").strip().lower()
            if role not in ("employee", "manager", "admin"):
                error = "Invalid role."

            # Keep legacy full-name field up to date
            full_name = f"{first_name} {last_name}".strip()

            active = True if request.form.get("active") == "on" else False

            birthday_str = request.form.get("birthday", "").strip()
            start_date_str = request.form.get("start_date", "").strip()
            end_date_str = request.form.get("end_date", "").strip()

            reporting_manager_id_str = (request.form.get("reporting_manager_id") or "").strip()

            # Validate name fields
            if not error:
                if not first_name:
                    error = "First name is required."
                elif not last_name:
                    error = "Last name is required."
                else:
                    existing = (
                        Employee.query
                        .filter(Employee.name == full_name, Employee.id != emp.id)
                        .first()
                    )
                    if existing:
                        error = "Another employee with that name already exists."

            if not error:
                emp.first_name = first_name
                emp.last_name = last_name
                emp.department = department if department else None
                emp.role = role

                emp.name = full_name
                emp.active = active

                # Birthday
                if birthday_str:
                    bday = parse_birthday(birthday_str)
                    if not bday:
                        error = "Invalid birthday date."
                    else:
                        emp.birthday = bday
                else:
                    emp.birthday = None

                # Start / End dates
                sd = parse_date_input(start_date_str)
                ed = parse_date_input(end_date_str)

                if start_date_str and not sd:
                    error = "Invalid start date."
                elif end_date_str and not ed:
                    error = "Invalid end date."
                elif sd and ed and ed < sd:
                    error = "End date cannot be earlier than start date."
                else:
                    emp.start_date = sd if sd else None
                    emp.end_date = ed if ed else None

                # Reporting manager (nullable)
                if reporting_manager_id_str:
                    try:
                        emp.reporting_manager_id = int(reporting_manager_id_str)
                    except ValueError:
                        emp.reporting_manager_id = None
                else:
                    emp.reporting_manager_id = None

                # --- Login handling (moved from Manage Users) ---
                # If an email is provided, we create/update the linked User record.
                # If no email is provided, we leave login as-is (or no login).
                if email:
                    existing_username_user = User.query.filter(User.username == email).first()
                    if existing_username_user and (not linked_user or existing_username_user.id != linked_user.id):
                        error = "That email/username is already in use by another user."

                    if not error:
                        if linked_user is None:
                            # Creating a new login requires a password
                            if not password:
                                error = "Password is required when creating a new login."
                            elif password != confirm_password:
                                error = "Passwords do not match."
                            else:
                                linked_user = User(
                                    username=email,
                                    role=(emp.role or "employee"),
                                    active=emp.active,
                                    employee_id=emp.id,
                                )
                                linked_user.set_password(password)
                                db.session.add(linked_user)
                        else:
                            # Update existing login
                            linked_user.username = email
                            linked_user.role = (emp.role or "employee")
                            linked_user.active = emp.active

                            # Only change password if provided
                            if password or confirm_password:
                                if password != confirm_password:
                                    error = "Passwords do not match."
                                elif not password:
                                    error = "Password cannot be empty."
                                else:
                                    linked_user.set_password(password)
                else:
                    # No email submitted: keep existing linked_user as-is for now
                    pass

                
                if not error:
                    db.session.commit()
                    flash("Employee details saved.", "success")
                    return redirect(url_for("manage_employees"))

        # -------------------------
        # B) Add / update entitlement
        # -------------------------
        elif form_action == "add_entitlement":
            # Admins do not have leave days allocated (server-side enforcement)
            if (emp.role or "").lower() == "admin":
                flash("Admins do not have leave days allocated.", "warning")
                return redirect(url_for("edit_employee", employee_id=emp.id))

            ent_year_str = (request.form.get("entitlement_year") or "").strip()
            ent_days_str = (request.form.get("entitlement_days") or "").strip()
            is_edit_mode_post = (request.form.get("is_edit_mode") or "").strip() == "1"

            if not ent_year_str or not ent_days_str:
                error = "Year and leave days are required."
            else:
                try:
                    ent_year = int(ent_year_str)
                    ent_days = float(ent_days_str)
                except ValueError:
                    error = "Invalid year or leave days."

            if not error:
                ent = (
                    Entitlement.query
                    .filter_by(employee_id=emp.id, year=ent_year)
                    .first()
                )

                if is_edit_mode_post:
                    # Edit mode: must already exist
                    if not ent:
                        error = "That year does not exist. Use Add to create it."
                    else:
                        ent.days = ent_days
                else:
                    # Add mode: must NOT already exist
                    if ent:
                        error = "That year already exists. Use the edit icon to change it."
                    else:
                        db.session.add(
                            Entitlement(employee_id=emp.id, year=ent_year, days=ent_days)
                        )

            if not error:
                db.session.commit()
                flash("Leave days saved.", "success")
                return redirect(url_for("edit_employee", employee_id=emp.id))

        else:
            error = "Unknown form submission."

    # Split-name values for display (derive from emp.name for legacy rows)
    first_name_value = emp.first_name or ""
    last_name_value = emp.last_name or ""
    if not first_name_value and not last_name_value and emp.name:
        parts = emp.name.split()
        if len(parts) == 1:
            first_name_value = parts[0]
        elif len(parts) >= 2:
            first_name_value = " ".join(parts[:-1])
            last_name_value = parts[-1]

    department_value = emp.department or ""

    # Ensure role has a safe display value even if older rows exist
    if not emp.role:
        emp.role = "employee"

    return render_template(
        "edit_employee.html",
        employee=emp,
        error=error,
        entitlement_year_value=entitlement_year_value,
        entitlement_days_value=entitlement_days_value,
        is_edit_mode=is_edit_mode,
        manager_employees=manager_employees,
        first_name_value=first_name_value,
        last_name_value=last_name_value,
        department_value=department_value,
        username_value=username_value,
    )

@app.route("/admin/employee/<int:employee_id>/entitlement/<int:year>/delete", methods=["POST"])
def delete_entitlement(employee_id, year):
    if not g.is_admin:
        return redirect(url_for("login"))

    emp = Employee.query.get_or_404(employee_id)

    # Delete any leave entries for this employee in that year
    entries = (
        LeaveEntry.query
        .filter(
            LeaveEntry.employee_id == emp.id,
            db.extract("year", LeaveEntry.date) == year,
        )
        .all()
    )
    for entry in entries:
        db.session.delete(entry)

    # Delete the entitlement for that year, if it exists
    ent = Entitlement.query.filter_by(employee_id=emp.id, year=year).first()
    if ent:
        db.session.delete(ent)

    db.session.commit()

    return redirect(url_for("edit_employee", employee_id=emp.id))

@app.route("/admin/employee/<int:employee_id>/archive", methods=["POST"])
def archive_employee(employee_id):
    if not g.is_admin:
        return redirect(url_for("login"))

    emp = Employee.query.get_or_404(employee_id)

    # Enforce end_date before archiving
    if emp.end_date is None:
        flash("Please set an End date before archiving this user.", "warning")
        return redirect(url_for("edit_employee", employee_id=emp.id))

    emp.active = False

    # Recommended: disable linked logins
    for u in list(emp.users):
        u.active = False

    db.session.commit()

    flash(f"{emp.name} has been archived.", "success")
    return redirect(url_for("manage_employees"))

@app.route("/admin/employee/<int:employee_id>/restore", methods=["POST"])
def restore_employee(employee_id):
    if not g.is_admin:
        return redirect(url_for("login"))

    emp = Employee.query.get_or_404(employee_id)

    # Restore (un-archive)
    emp.active = True

    # Recommended: re-enable linked login accounts
    for u in list(emp.users):
        u.active = True

    db.session.commit()

    return redirect(url_for("manage_employees", show_archived=1))

@app.route("/admin/users", methods=["GET"])
def manage_users():
    if not g.is_admin:
        return redirect(url_for("login"))

    users = User.query.order_by(User.username).all()
    employees = Employee.query.order_by(Employee.name).all()
    error = request.args.get("error")

    return render_template(
        "manage_users.html",
        users=users,
        employees=employees,
        error=error,
    )

@app.route("/admin/users/create", methods=["POST"])
def create_user():
    if not g.is_admin:
        return redirect(url_for("login"))

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or "employee").strip()
    employee_id_str = (request.form.get("employee_id") or "").strip()

    if not username or not password:
        return redirect(
            url_for("manage_users", error="Username and password are required.")
        )

    existing = User.query.filter_by(username=username).first()
    if existing:
        return redirect(
            url_for("manage_users", error="A user with that username already exists.")
        )

    # Normalise role
    if role not in ("admin", "manager", "employee"):
        # Treat legacy "user" as employee
        if role == "user":
            role = "employee"
        else:
            role = "employee"

    # Optional employee link
    employee_id = None
    if employee_id_str:
        try:
            employee_id = int(employee_id_str)
        except ValueError:
            employee_id = None

    user = User(
        username=username,
        role=role,
        active=True,
        employee_id=employee_id,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return redirect(url_for("manage_users"))

@app.route("/admin/users/<int:user_id>/update", methods=["POST"])
def update_user(user_id):
    if not g.is_admin:
        return redirect(url_for("login"))

    user = User.query.get_or_404(user_id)
    is_self = g.user is not None and g.user.id == user.id

    # Basic fields from the form
    username_raw = (request.form.get("username") or "").strip()
    role = (request.form.get("role") or user.role).strip()
    active = True if request.form.get("active") == "on" else False
    new_password = request.form.get("password") or ""
    employee_id_str = (request.form.get("employee_id") or "").strip()

    # Normalise role
    if role not in ("admin", "manager", "employee"):
        # Treat legacy "user" as employee
        if role == "user":
            role = "employee"
        else:
            role = user.role

    # Optional employee linkage
    if employee_id_str:
        try:
            employee_id = int(employee_id_str)
        except ValueError:
            employee_id = user.employee_id
    else:
        employee_id = None

    # If editing your own account, DO NOT change your role/active from the form
    if is_self:
        role = user.role
        active = user.active

    # Prevent removing the last active admin
    was_admin = (user.role == "admin" and user.active)
    will_remove_admin = (role != "admin" or not active)

    if was_admin and will_remove_admin:
        other_admins = (
            User.query
            .filter(
                User.id != user.id,
                User.role == "admin",
                User.active.is_(True),
            )
            .count()
        )
        if other_admins == 0:
            # This is the last active admin; don't allow demotion/deactivation
            return redirect(
                url_for(
                    "manage_users",
                    error="You cannot remove the last active admin.",
                )
            )

    # Apply updates
    if username_raw:
        user.username = username_raw  # update email/username

    user.role = role
    user.active = active
    user.employee_id = employee_id

    if new_password:
        user.set_password(new_password)

    db.session.commit()

    return redirect(url_for("manage_users"))


# ---------------------------
# Run (for local development)
# ---------------------------

if __name__ == "__main__":
    app.run(debug=True)


