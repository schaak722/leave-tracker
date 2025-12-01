from datetime import datetime, date, timedelta
import calendar
import os
from collections import defaultdict

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, jsonify, abort
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

# Prefer DATABASE_URL (Postgres in production), fall back to SQLite locally
database_url = os.environ.get("DATABASE_URL")

if not database_url:
    # Local development fallback: SQLite file next to app.py
    default_db_path = os.path.join(os.path.dirname(__file__), "leave_calendar.db")
    database_url = f"sqlite:///{default_db_path}"

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

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
    name = db.Column(db.String(100), unique=True, nullable=False)
    active = db.Column(db.Boolean, default=True)
    birthday = db.Column(db.Date, nullable=True)  # Birthday stored on the employee

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
    role = db.Column(db.String(20), default="admin")  # "admin" or "user"
    active = db.Column(db.Boolean, default=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

ensure_admin_user()

# ---------------------------
# Helpers
# ---------------------------

@app.before_request
def load_logged_in_user():
    g.user = None
    g.is_admin = False

    user_id = session.get("user_id")
    if user_id is not None:
        user = User.query.get(user_id)
        if user and user.active:
            g.user = user
            g.is_admin = (user.role == "admin")

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


def compute_year_summary(year: int):
    """
    Return:
      - employees (only those with entitlement for this year & active),
      - per_employee list with entitlement/taken/remaining,
      - cell_codes mapping "employeeId_YYYY-MM-DD" -> code ("F"/"H").
    """
    # Only employees who have an entitlement for this year AND are active
    employees = (
        db.session.query(Employee)
        .join(Entitlement, Employee.id == Entitlement.employee_id)
        .filter(Entitlement.year == year, Employee.active.is_(True))
        .order_by(Employee.name)
        .all()
    )

    entitlements = Entitlement.query.filter_by(year=year).all()
    entries = (
        LeaveEntry.query
        .filter(db.extract("year", LeaveEntry.date) == year)
        .all()
    )

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


def parse_birthday(birthday_str: str):
    """
    Try to parse a birthday from several common formats.
    Returns a date object or None.
    Accepts:
      - 1978-07-22
      - 22/07/1978
      - 22-07-1978
    """
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


@app.route("/update_cell", methods=["POST"])
def update_cell():
    if not g.is_admin:
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

@app.route("/admin/add_employee", methods=["GET", "POST"])
def add_employee():
    """
    If name exists: update leave days (entitlement) for that year.
    If not: create employee + leave days record.
    """
    if not g.is_admin:
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        year = int(request.form.get("year"))
        entitlement_days = float(request.form.get("entitlement_days"))
        birthday_str = request.form.get("birthday", "").strip()

        if not name:
            return render_template(
                "base.html",
                content="<p class='text-danger'>Name is required</p>",
            )

        # Reuse existing employee if same name
        emp = Employee.query.filter_by(name=name).first()
        if not emp:
            emp = Employee(name=name, active=True)
            db.session.add(emp)
            db.session.flush()  # get emp.id

        # Parse and set birthday if provided
        bday = parse_birthday(birthday_str)
        if bday:
            emp.birthday = bday

        ent = Entitlement.query.filter_by(employee_id=emp.id, year=year).first()
        if ent:
            ent.days = entitlement_days
        else:
            ent = Entitlement(
                employee_id=emp.id,
                year=year,
                days=entitlement_days,
            )
            db.session.add(ent)

        db.session.commit()
        return redirect(url_for("manage_employees"))

    current_year = datetime.now().year
    return render_template(
        "base.html",
        content=f"""
        <h2>Add / Update Leave Days</h2>
        <p>If the name already exists, this will <strong>update</strong> their leave days for that year.</p>
        <form method='post'>
            <div class='mb-3'>
              <label class='form-label'>Name:
                <input type='text' name='name' class='form-control'>
              </label>
            </div>
            <div class='mb-3'>
              <label class='form-label'>Birthday:
                <input type='date' name='birthday' class='form-control'>
              </label>
            </div>
            <div class='mb-3'>
              <label class='form-label'>Year:
                <input type='number' name='year' value='{current_year}' class='form-control'>
              </label>
            </div>
            <div class='mb-3'>
              <label class='form-label'>Leave days:
                <input type='number' step='0.5' name='entitlement_days' class='form-control'>
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

    employees = Employee.query.order_by(Employee.name).all()
    return render_template("manage_employees.html", employees=employees)

@app.route("/admin/employee/<int:employee_id>/edit", methods=["GET", "POST"])
def edit_employee(employee_id):
    if not g.is_admin:
        return redirect(url_for("login"))

    emp = Employee.query.get_or_404(employee_id)
    error = None

    # Default to current year for leave days editor
    current_year = datetime.now().year
    ent_for_current_year = (
        Entitlement.query
        .filter_by(employee_id=emp.id, year=current_year)
        .first()
    )
    current_year_ent_days = ent_for_current_year.days if ent_for_current_year else ""

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        active = True if request.form.get("active") == "on" else False
        birthday_str = request.form.get("birthday", "").strip()

        ent_year_str = request.form.get("ent_year", "").strip()
        ent_days_str = request.form.get("ent_days", "").strip()

        # --- validate name ---
        if not name:
            error = "Name is required"
        else:
            # Check for duplicate name on another employee
            existing = (
                Employee.query
                .filter(Employee.name == name, Employee.id != emp.id)
                .first()
            )
            if existing:
                error = "Another employee with that name already exists."

        # --- validate leave days (if provided) ---
        ent_year = None
        ent_days = None
        if not error and (ent_year_str or ent_days_str):
            try:
                ent_year = int(ent_year_str)
                ent_days = float(ent_days_str)
            except ValueError:
                error = "Invalid year or leave days."

        # --- apply changes if no errors ---
        if not error:
            emp.name = name
            emp.active = active

            # Parse and set birthday
            bday = parse_birthday(birthday_str)
            emp.birthday = bday if bday else None

            # If leave days info was provided, update/create that year
            if ent_year is not None and ent_days is not None:
                ent = (
                    Entitlement.query
                    .filter_by(employee_id=emp.id, year=ent_year)
                    .first()
                )
                if ent:
                    ent.days = ent_days
                else:
                    ent = Entitlement(
                        employee_id=emp.id,
                        year=ent_year,
                        days=ent_days,
                    )
                    db.session.add(ent)

            db.session.commit()
            return redirect(url_for("manage_employees"))

        # If there was an error, keep what user typed for ent fields
        if ent_year_str:
            try:
                current_year = int(ent_year_str)
            except ValueError:
                pass
        if ent_days_str:
            current_year_ent_days = ent_days_str

    return render_template(
        "edit_employee.html",
        employee=emp,
        error=error,
        current_year=current_year,
        current_year_ent_days=current_year_ent_days,
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

@app.route("/admin/employee/<int:employee_id>/delete", methods=["POST"])
def delete_employee(employee_id):
    if not g.is_admin:
        return redirect(url_for("login"))

    emp = Employee.query.get_or_404(employee_id)

    # Delete entitlements and leave entries first
    for ent in list(emp.entitlements):
        db.session.delete(ent)
    for entry in list(emp.leave_entries):
        db.session.delete(entry)

    db.session.delete(emp)
    db.session.commit()

    return redirect(url_for("manage_employees"))

@app.route("/admin/users", methods=["GET"])
def manage_users():
    if not g.is_admin:
        return redirect(url_for("login"))

    users = User.query.order_by(User.username).all()
    error = request.args.get("error")
    return render_template("manage_users.html", users=users, error=error)


@app.route("/admin/users/create", methods=["POST"])
def create_user():
    if not g.is_admin:
        return redirect(url_for("login"))

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or "user").strip()

    if not username or not password:
        return redirect(url_for("manage_users", error="Username and password are required."))

    existing = User.query.filter_by(username=username).first()
    if existing:
        return redirect(url_for("manage_users", error="A user with that username already exists."))

    if role not in ("admin", "user"):
        role = "user"

    user = User(
        username=username,
        role=role,
        active=True,
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

    # Basic fields
    role = (request.form.get("role") or user.role).strip()
    active = True if request.form.get("active") == "on" else False
    new_password = request.form.get("password") or ""

    if role not in ("admin", "user"):
        role = user.role

    # Optional: avoid locking yourself out completely
    # (We keep it simple for now and trust you not to disable the only admin.)

    user.role = role
    user.active = active

    if new_password:
        user.set_password(new_password)

    db.session.commit()

    return redirect(url_for("manage_users"))

# ---------------------------
# Run (for local development)
# ---------------------------

if __name__ == "__main__":
    app.run(debug=True)


