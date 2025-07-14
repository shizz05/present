from flask import Flask, render_template, request, redirect, url_for, session, flash
import psycopg2
import bcrypt
from uuid import uuid4
from datetime import datetime, timedelta
import smtplib
from email.message import EmailMessage
import os
from werkzeug.utils import secure_filename
from flask import jsonify
import re
import io
from flask import send_file


app = Flask(__name__)
app.secret_key = "Apollo$ecureTyrePlatform@2025"


# ------------------------ PostgreSQL Connection ------------------------
from urllib import parse as urlparse
import os
import psycopg2


def get_db_connection():
    return psycopg2.connect(
        dbname="admin",
        user="postgres",
        password="apolloatr",
        host="localhost",
        port="5432",
    )


# ------------------------ Send Reset Email ------------------------
def send_reset_email(to_email, reset_link):
    EMAIL_ADDRESS = "kushikabillionaire@gmail.com"
    EMAIL_PASSWORD = "xsck vmhp kifd ujxw"  # App password

    msg = EmailMessage()
    msg["Subject"] = "Apollo Tyres Password Reset Link"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    msg.set_content(
        f"""
Dear Admin,

We received a password reset request for your Apollo Tyres account.

Click the link below to reset your password (valid for 15 minutes):
{reset_link}

If you didn’t request this, please ignore this email.

Regards,
Apollo Tyres Security Team
"""
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)


# ------------------------ Routes ------------------------


@app.route("/")
def landing():
    return render_template("landing_page.html")


# ------------------------ Admin Login ------------------------
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")

        if not email.endswith("@apollotyres.com"):
            flash("Email must end with @apollotyres.com", "error")
            return render_template("loginad.html")

        conn = get_db_connection()
        cur = conn.cursor()

        # Check if admin exists in the current table
        cur.execute("SELECT password FROM admins WHERE email = %s", (email,))
        result = cur.fetchone()

        if result:
            # ✅ Admin exists: check password
            if bcrypt.checkpw(password.encode("utf-8"), result[0].encode("utf-8")):
                session["admin_email"] = email
                session["role"] = "admin"
                cur.execute(
                    "INSERT INTO login_logs (email, status) VALUES (%s, %s)",
                    (email, "success"),
                )
                conn.commit()
                cur.close()
                conn.close()
                return redirect(url_for("admin_panel"))
            else:
                # ❌ Password mismatch
                cur.execute(
                    "INSERT INTO login_logs (email, status) VALUES (%s, %s)",
                    (email, "failed - wrong password"),
                )
                conn.commit()
                flash("Invalid credentials", "error")
                cur.close()
                conn.close()
                return render_template("loginad.html")
        else:
            # 🛑 Admin was removed from DB
            cur.execute(
                "SELECT 1 FROM login_logs WHERE email = %s AND status = 'success' LIMIT 1",
                (email,),
            )
            existed_before = cur.fetchone()
            if existed_before:
                cur.execute(
                    "INSERT INTO login_logs (email, status) VALUES (%s, %s)",
                    (email, "denied - removed admin"),
                )
                conn.commit()
                flash("❌ This admin has been removed. Access denied.", "error")
                cur.close()
                conn.close()
                return render_template("loginad.html")

            # 🆘 Never registered as admin
            flash("❌ You are not registered as an admin.", "error")
            cur.close()
            conn.close()
            return render_template("loginad.html")

    return render_template("loginad.html")




# ------------------------ Admin Panel ------------------------
@app.route("/admin_panel")
def admin_panel():
    if "admin_email" not in session:
        return redirect(url_for("admin_login"))
    return render_template("admin.html")


# ------------------------ Logout ------------------------
@app.route("/logout")
def logout():
    role = session.get("role")
    email = session.get("admin_email") or session.get("user_email")

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        if role == "admin" and email:
            cur.execute("DELETE FROM admins WHERE email = %s", (email,))
        elif role == "user" and email:
            cur.execute("DELETE FROM users WHERE email = %s", (email,))

        cur.execute(
            "INSERT INTO login_logs (email, status) VALUES (%s, 'logout - removed')",
            (email,)
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        flash(f"Logout DB error: {e}", "error")
    finally:
        cur.close()
        conn.close()
        session.clear()

    return redirect(url_for("landing"))

# ------------------------ Generate Hashed Password ------------------------
@app.route("/generate_hash/<plaintext>")
def generate_hash(plaintext):
    hashed = bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    return f"<h4>Hashed password for '{plaintext}':</h4><code>{hashed}</code>"


# ------------------------ Forgot Password ------------------------
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM admins WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            token = str(uuid4())
            expires_at = datetime.now() + timedelta(minutes=15)
            cur.execute(
                "INSERT INTO reset_tokens (email, token, expires_at) VALUES (%s, %s, %s)",
                (email, token, expires_at),
            )
            conn.commit()
            reset_link = url_for("reset_password", token=token, _external=True)
            try:
                send_reset_email(email, reset_link)
                flash("A reset link has been sent to your email.", "info")
            except Exception as e:
                flash(f"Failed to send email: {str(e)}", "error")
        else:
            flash("Email not found in system", "error")

        cur.close()
        conn.close()

    return render_template("forgot_password.html")


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email, expires_at FROM reset_tokens WHERE token = %s", (token,))
    token_data = cur.fetchone()

    if not token_data:
        flash("Invalid or expired token", "error")
        return redirect(url_for("forgot_password"))

    email, expires_at = token_data
    if datetime.now() > expires_at:
        flash("Token has expired", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form["new_password"]
        hashed_password = bcrypt.hashpw(
            new_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        cur.execute(
            "UPDATE admins SET password = %s WHERE email = %s", (hashed_password, email)
        )
        cur.execute("DELETE FROM reset_tokens WHERE token = %s", (token,))
        conn.commit()
        flash("Password successfully updated. Please login.", "success")
        cur.close()
        conn.close()
        return redirect(url_for("admin_login"))

    cur.close()
    conn.close()
    return render_template("reset_password.html", token=token)


# ------------------------ Admin: Add Admin ------------------------
import re

@app.route("/add_admin", methods=["POST"])
def add_admin():
    if "admin_email" not in session:
        flash("Unauthorized access", "error")
        return redirect(url_for("admin_login"))

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "").strip()

    if not email or not password:
        flash("Email and password are required", "error")
        return redirect(url_for("admin_panel"))

    # ✅ Enforce apollotyres.com email format
    if not re.fullmatch(r"[a-zA-Z0-9._%+-]+@apollotyres\.com", email):
        flash("❌ Only Apollo Tyres emails are allowed", "error")
        return redirect(url_for("admin_panel"))

    conn = get_db_connection()
    cur = conn.cursor()

    # ✅ Hash the password
    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    try:
        # ✅ Try to insert only if it doesn't exist already
        cur.execute("""
            INSERT INTO admins (email, password)
            VALUES (%s, %s)
            ON CONFLICT (email) DO NOTHING
        """, (email, hashed_password))
        conn.commit()

        # ✅ Check if the insert succeeded
        cur.execute("SELECT * FROM admins WHERE email = %s", (email,))
        if cur.fetchone():
            flash("✅ Admin added or already exists", "success")
        else:
            flash("❌ Admin already exists", "error")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Database error: {e}", "error")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("admin_panel"))



# ------------------------ Admin: Update Password & Passcode ------------------------
@app.route("/admin_security_update", methods=["POST"])
def admin_security_update():
    if "admin_email" not in session:
        flash("Unauthorized", "error")
        return redirect(url_for("admin_login"))

    new_passcode = request.form["new_passcode"]
    current_pw = request.form["current_password"]
    new_pw = request.form["new_password"]
    confirm_pw = request.form["confirm_password"]
    admin_email = session["admin_email"]

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO system_settings (setting_key, setting_value)
        VALUES ('registration_passcode', %s)
        ON CONFLICT (setting_key) DO UPDATE
        SET setting_value = EXCLUDED.setting_value
    """,
        (new_passcode,),
    )
    conn.commit()

    if new_pw != confirm_pw:
        flash("New passwords do not match", "error")
    else:
        cur.execute("SELECT password FROM admins WHERE email = %s", (admin_email,))
        row = cur.fetchone()
        if not row or not bcrypt.checkpw(
            current_pw.encode("utf-8"), row[0].encode("utf-8")
        ):
            flash("Incorrect current password", "error")
        else:
            new_hashed_pw = bcrypt.hashpw(
                new_pw.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")
            cur.execute(
                "UPDATE admins SET password = %s WHERE email = %s",
                (new_hashed_pw, admin_email),
            )
            conn.commit()
            flash("Passcode and password updated successfully", "success")

    cur.close()
    conn.close()
    return redirect(url_for("admin_panel"))


# ------------------------ USER FLOW ------------------------


@app.route("/user_login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor()

        # 🔍 Check if the user exists in the users table
        cur.execute("SELECT password FROM users WHERE email = %s", (email,))
        row = cur.fetchone()

        if row:
            # ✅ Existing user: verify password
            if bcrypt.checkpw(password.encode("utf-8"), row[0].encode("utf-8")):
                cur.execute(
                    "INSERT INTO login_logs (email, status) VALUES (%s, 'success')",
                    (email,),
                )
                conn.commit()
                session["user_email"] = email
                session["role"] = "user"
                cur.close()
                conn.close()
                return redirect(url_for("user_dashboard"))
            else:
                # ❌ Wrong password
                cur.execute(
                    "INSERT INTO login_logs (email, status) VALUES (%s, 'failed - wrong password')",
                    (email,),
                )
                conn.commit()
                flash("Incorrect password", "error")
                cur.close()
                conn.close()
                return redirect(url_for("user_login"))

        # 🔄 User previously existed (was removed): allow re-verification via passcode
        cur.execute(
            "SELECT 1 FROM login_logs WHERE email = %s AND status ILIKE 'success' LIMIT 1",
            (email,),
        )
        existed = cur.fetchone()
        if existed:
            session["temp_user_email"] = email
            session["temp_user_password"] = password
            flash("Re-verification required. Please enter passcode.", "info")
            cur.close()
            conn.close()
            return redirect(url_for("user_passcode"))

        # 🆕 New user flow (first-time registration)
        session["temp_user_email"] = email
        session["temp_user_password"] = password
        cur.close()
        conn.close()
        return redirect(url_for("user_passcode"))

    return render_template("loginus.html")


# Step 2: User enters passcode (only shown for new users)
@app.route("/user_passcode", methods=["GET", "POST"])
def user_passcode():
    if "temp_user_email" not in session or "temp_user_password" not in session:
        return redirect(url_for("user_login"))

    if request.method == "POST":
        passcode = request.form["passcode"].strip()

        conn = get_db_connection()
        cur = conn.cursor()

        # Get the registration passcode from settings
        cur.execute(
            "SELECT setting_value FROM system_settings WHERE setting_key = 'registration_passcode'"
        )
        row = cur.fetchone()

        if not row or row[0] != passcode:
            flash("Invalid passcode", "error")
            return render_template("user_passcode.html")

        email = session["temp_user_email"]
        password = session["temp_user_password"]

        # Check again (safety): if user was somehow registered meanwhile
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()

        if not existing_user:
            # Register user
            hashed_pw = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")
            cur.execute(
                "INSERT INTO users (email, password) VALUES (%s, %s)",
                (email, hashed_pw),
            )
            flash("User registered successfully.", "success")
        else:
            flash("User already registered. Logging you in...", "info")

        # Log login
        cur.execute(
            "INSERT INTO login_logs (email, status) VALUES (%s, 'success')",
            (email,),
        )

        conn.commit()
        cur.close()
        conn.close()

        session["user_email"] = email
        session.pop("temp_user_email", None)
        session.pop("temp_user_password", None)
        return redirect(url_for("user_dashboard"))

    return render_template("user_passcode.html")


# Dashboard
@app.route("/user_dashboard")
def user_dashboard():
    if "user_email" not in session:
        return redirect(url_for("user_login"))
    return render_template("user.html")

    # ------------------------ User Forgot Password ------------------------


@app.route("/user_forgot_password", methods=["GET", "POST"])
def user_forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            token = str(uuid4())
            expires_at = datetime.now() + timedelta(minutes=15)
            cur.execute(
                "INSERT INTO reset_tokens (email, token, expires_at) VALUES (%s, %s, %s)",
                (email, token, expires_at),
            )
            conn.commit()
            reset_link = url_for("user_reset_password", token=token, _external=True)
            try:
                send_reset_email(email, reset_link)
                flash("A reset link has been sent to your email.", "info")
            except Exception as e:
                flash(f"Failed to send email: {str(e)}", "error")
        else:
            flash("Email not found in system", "error")

        cur.close()
        conn.close()

    return render_template("user_forgot_password.html")


# ------------------------ User Reset Password ------------------------
@app.route("/user_reset_password/<token>", methods=["GET", "POST"])
def user_reset_password(token):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email, expires_at FROM reset_tokens WHERE token = %s", (token,))
    token_data = cur.fetchone()

    if not token_data:
        flash("Invalid or expired token", "error")
        return redirect(url_for("user_forgot_password"))

    email, expires_at = token_data
    if datetime.now() > expires_at:
        flash("Token has expired", "error")
        return redirect(url_for("user_forgot_password"))

    if request.method == "POST":
        new_password = request.form["new_password"]
        hashed_password = bcrypt.hashpw(
            new_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        cur.execute(
            "UPDATE users SET password = %s WHERE email = %s", (hashed_password, email)
        )
        cur.execute("DELETE FROM reset_tokens WHERE token = %s", (token,))
        conn.commit()
        flash("Password successfully updated. Please login.", "success")
        cur.close()
        conn.close()
        return redirect(url_for("user_login"))

    cur.close()
    conn.close()
    return render_template("user_reset_password.html", token=token)


@app.route("/upload_inc_file", methods=["POST"])
def upload_inc_file():
    if "admin_email" not in session:
        flash("Unauthorized access", "error")
        return redirect(url_for("admin_login"))

    file = request.files.get("inc_file")
    if not file or file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("admin_panel"))

    if not file.filename.endswith(".inc"):
        flash("Only .inc files allowed.", "error")
        return redirect(url_for("admin_panel"))

    filename = secure_filename(file.filename)
    filepath = os.path.join("uploads", filename)
    os.makedirs("uploads", exist_ok=True)
    file.save(filepath)

    conn = None
    cur = None
    errors = []
    success_count = 0

    try:
        with open(filepath, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        conn = get_db_connection()
        cur = conn.cursor()

        i = 0
        while i < len(lines):
            line = lines[i]

            if line.upper().startswith("*MATERIAL"):
                try:
                    # ✅ Backtrack to find category (PCR, TBR etc.)
                    category = "UNKNOWN"
                    for j in range(i - 1, -1, -1):
                        cat_match = re.search(r"\*+([A-Z0-9]+)_", lines[j])
                        if cat_match:
                            category = cat_match.group(1)
                            break

                    # ✅ Compound Name
                    compound_match = re.search(
                        r"name\s*=\s*([A-Z0-9_\-]+)", line, re.IGNORECASE
                    )
                    if not compound_match:
                        errors.append(f"Line {i+1}: Invalid or missing compound name.")
                        i += 1
                        continue
                    compound_name = compound_match.group(1).strip()
                    if not re.match(r"^[A-Z0-9_-]+$", compound_name):
                        errors.append(
                            f"Line {i+1}: Invalid compound name '{compound_name}'. Only A-Z, 0-9, -, _ allowed."
                        )
                        i += 1
                        continue

                    # ✅ Density line check
                    if i + 2 >= len(lines) or not lines[i + 1].upper().startswith(
                        "*DENSITY"
                    ):
                        errors.append(f"Line {i+2}: Missing *DENSITY line.")
                        i += 1
                        continue
                    density_line = lines[i + 2]
                    if not re.fullmatch(r"\d+(\.\d+)?E-\d+,", density_line.strip()):
                        errors.append(
                            f"Line {i+3}: Invalid density format '{density_line}'. Expected format like '1.166E-09,'"
                        )
                        i += 3
                        continue
                    density = density_line.strip().rstrip(",")

                    # ✅ Model & Reduced Polynomial
                    if i + 4 >= len(lines) or (
                        "*HYPERELASTIC" not in lines[i + 3].upper()
                        and "*VISCOELASTIC" not in lines[i + 3].upper()
                    ):
                        errors.append(
                            f"Line {i+4}: Missing model line (*HYPERELASTIC or *VISCOELASTIC)."
                        )
                        i += 4
                        continue
                    model_line = lines[i + 3].upper()
                    model = (
                        "HYPERELASTIC"
                        if "HYPERELASTIC" in model_line
                        else "VISCOELASTIC"
                    )

                    n_match = re.search(r"N\s*=\s*([123])", model_line)
                    if not n_match:
                        errors.append(
                            f"Line {i+4}: Missing or invalid N value in model line."
                        )
                        i += 4
                        continue
                    n = int(n_match.group(1))

                    poly_line = lines[i + 4]
                    coeffs = [v.strip() for v in poly_line.split(",") if v.strip()]
                    if len(coeffs) != 2 * n or not all(
                        re.match(r"^-?\d+(\.\d+)?$", c) for c in coeffs
                    ):
                        errors.append(
                            f"Line {i+5}: Invalid Reduced Polynomial format. Expected {2*n} numeric values for N={n}."
                        )
                        i += 5
                        continue

                    reduced_polynomial = ",".join(coeffs)

                    # ✅ INSERT or UPDATE existing compound
                    cur.execute(
                        """
                        INSERT INTO compounds (compound_name, category, density, model, reduced_polynomial, source_file)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (compound_name, category, model)
                        DO UPDATE SET
                            density = EXCLUDED.density,
                            reduced_polynomial = EXCLUDED.reduced_polynomial,
                            source_file = EXCLUDED.source_file
                    """,
                        (
                            compound_name,
                            category,
                            density,
                            model,
                            reduced_polynomial,
                            filename,
                        ),
                    )

                    success_count += 1
                    i += 6

                except Exception as e:
                    errors.append(f"Line {i+1}: Unexpected parsing error: {str(e)}")
                    i += 1
            else:
                i += 1

        conn.commit()

    except Exception as e:
        errors.append(f"General error: {str(e)}")
        print("❌ Upload error:", e)

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    if success_count > 0:
        print(f" logging UPLOAD for: {filename}")
        log_audit("UPLOAD", session.get("admin_email"), None, None, None, filename)
    if errors:
        for e in errors:
            flash(f"❌ {e}", "error")
        flash(
            f"⚠️ File upload completed with {len(errors)} error(s), {success_count} compound(s) processed.",
            "error",
        )
    else:
        flash(
            f"✅ File uploaded successfully. {success_count} compound(s) processed.",
            "success",
        )
    return redirect(url_for("admin_panel"))


@app.route("/compound_suggestions")
def compound_suggestions():
    prefix = request.args.get("q", "").lower()  # Match 'q' from frontend JavaScript

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT DISTINCT compound_name
        FROM compounds
        WHERE LOWER(compound_name) LIKE %s
        ORDER BY compound_name
        LIMIT 10
    """,
        (prefix + "%",),
    )

    suggestions = [row[0] for row in cur.fetchall()]
    cur.close()
    conn.close()

    return jsonify(suggestions)


@app.route("/compound_density")
def compound_density():
    name = request.args.get("name", "").strip()
    category = request.args.get("category", "").strip()

    print(f"Querying for compound: {name}, category: {category}")  # DEBUG

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT density FROM compounds
        WHERE LOWER(compound_name) = LOWER(%s)
          AND LOWER(category) = LOWER(%s)
        LIMIT 1
    """,
        (name, category),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    print("Result:", row)  # DEBUG

    return jsonify({"density": row[0] if row else None})


@app.route("/compound_full_data", methods=["POST"])
def get_compound_full_data():
    print("✅ /compound_full_data route is active")
    data = request.get_json()
    name = data.get("compound_name")
    category = data.get("category")
    model = data.get("model", "").upper()
    selected_n = data.get("n")

    try:
        selected_n = int(selected_n)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid N value"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT compound_name, category, density, model, reduced_polynomial
        FROM compounds
        WHERE LOWER(compound_name) = LOWER(%s)
          AND LOWER(category) = LOWER(%s)
          AND LOWER(model) = LOWER(%s)
        LIMIT 1
        """,
        (name, category, model),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row:
        reduced = row[4]
        coeffs = [x.strip() for x in reduced.split(",") if x.strip()]
        expected_coeffs = selected_n * 2

    if model == "HYPERELASTIC" or model == "VISCOELASTIC":
        if len(coeffs) == expected_coeffs:
            return jsonify(
                {
                    "compound_name": row[0],
                    "category": row[1],
                    "density": row[2],
                    "model": row[3],
                    "reduced_polynomial": row[4],
                }
            )
        else:
            return (
                jsonify({"error": f"Reduced polynomial for N={selected_n} not found."}),
                404,
            )
    else:
        # For other models (future), just return without N-check
        return jsonify(
            {
                "compound_name": row[0],
                "category": row[1],
                "density": row[2],
                "model": row[3],
                "reduced_polynomial": row[4],
            }
        )


import matplotlib.pyplot as plt
import io
import base64


# Function to generate a graph image for Reduced Polynomial data
def generate_reduced_polynomial_graph(coefficients):
    """
    coefficients: list of floats (length 2N, eg: C10, C20..., D1, D2...)
    Returns: base64 image string
    """
    N = len(coefficients) // 2
    C = coefficients[:N]
    D = coefficients[N:]

    strain = [i * 0.1 for i in range(21)]  # 0 to 2 in 0.1 steps
    stress = []

    for e in strain:
        W = 0
        for i in range(N):
            W += C[i] * (e ** (2 * (i + 1)))
        for j in range(N):
            W += D[j] * e
        stress.append(W)

    # Plotting
    fig, ax = plt.subplots()
    ax.plot(strain, stress, label="Reduced Polynomial Fit", marker="o", color="cyan")
    ax.set_title("Reduced Polynomial Graph")
    ax.set_xlabel("Strain")
    ax.set_ylabel("Stress")
    ax.grid(True)
    ax.legend()

    # Save plot to base64
    buf = io.BytesIO()
    plt.savefig(buf, format="png", bbox_inches="tight", facecolor="black")
    plt.close(fig)
    buf.seek(0)
    graph_url = base64.b64encode(buf.read()).decode("utf-8")
    return f"data:image/png;base64,{graph_url}"


# Example usage
coeffs = [0.7, -0.1, 0.04, 0.03, 0, 0]  # Sample Reduced Polynomial (N=3)
graph_image_url = generate_reduced_polynomial_graph(coeffs)


# You can now embed `graph_image_url` in an <img src="..."> tag in your Flask template
@app.route("/generate_graph")
def generate_graph():
    import matplotlib.pyplot as plt
    import io
    from flask import send_file, request

    name = request.args.get("name")
    category = request.args.get("category")
    model = request.args.get("model")
    reduced_poly = request.args.get("reduced_poly")

    try:
        points = [float(p.strip()) for p in reduced_poly.split(",")]
        x = list(range(1, len(points) + 1))
        y = points

        fig, ax = plt.subplots()
        ax.plot(x, y, marker="o")
        ax.set_title(f"{name} - {category} - {model}")
        ax.set_xlabel("Coefficient Index")
        ax.set_ylabel("Value")
        ax.grid(True)

        buf = io.BytesIO()
        plt.savefig(buf, format="png")
        buf.seek(0)
        plt.close(fig)

        return send_file(buf, mimetype="image/png")
    except Exception as e:
        return f"Error generating graph: {e}", 500


# --- AJAX: SUGGESTIONS FOR COMPOUND DELETE ---
@app.route("/compound_delete_suggestions")
def compound_delete_suggestions():
    query = request.args.get("q", "").strip().upper()
    suggestions = []

    if not query:
        return jsonify(suggestions)

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT DISTINCT compound_name
            FROM compounds
            WHERE UPPER(compound_name) LIKE %s
            ORDER BY compound_name
            LIMIT 10
            """,
            (f"{query}%",),
        )
        suggestions = [row[0] for row in cur.fetchall()]
    except Exception as e:
        print("❌ Suggestion fetch error:", e)
    finally:
        cur.close()
        conn.close()

    return jsonify(suggestions)


# --- DELETE ROUTE ---
@app.route("/delete_compound", methods=["POST"])
def delete_compound():
    if "admin_email" not in session:
        flash("Unauthorized access", "error")
        return redirect(url_for("admin_login"))

    delete_type = request.form.get("delete_type")

    if delete_type == "file":
        filename = request.form.get("filename", "").strip()

        if not filename or not filename.endswith(".inc"):
            flash("❌ Invalid file name. Only .inc files allowed.", "error")
            return redirect(url_for("admin_panel"))

        filepath = os.path.join("uploads", secure_filename(filename))
        conn = get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                "SELECT COUNT(*) FROM compounds WHERE source_file = %s", (filename,)
            )
            count = cur.fetchone()[0]
            if count == 0:
                flash("❌ No data found for the provided file name.", "error")
                return redirect(url_for("admin_panel"))

            cur.execute("DELETE FROM compounds WHERE source_file = %s", (filename,))

            if os.path.exists(filepath):
                os.remove(filepath)
                flash(
                    f"✅ File '{filename}' and associated data deleted successfully.",
                    "success",
                )
            else:
                flash(
                    f"⚠️ File '{filename}' not found in uploads folder. Associated data removed from DB.",
                    "warning",
                )

            # ✅ Log audit with print debug
            print(f"🛠️ Logging DELETE_FILE for: {filename}")
            log_audit(
                action_type="DELETE_FILE",
                actor_email=session.get("admin_email"),
                file_name=filename,
            )

            conn.commit()

        except Exception as e:
            print("❌ Delete file error:", e)
            flash(f"❌ Error deleting file or compounds: {str(e)}", "error")
        finally:
            cur.close()
            conn.close()

        return redirect(url_for("admin_panel"))

    elif delete_type == "compound":
        compound_name = request.form.get("compound_name", "").strip()
        category = request.form.get("category", "").strip()

        if not compound_name or not category:
            flash("❌ Compound name and category are required.", "error")
            return redirect(url_for("admin_panel"))

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                "SELECT model FROM compounds WHERE compound_name = %s AND category = %s",
                (compound_name, category),
            )
            row = cur.fetchone()

            if not row:
                flash(
                    "❌ Invalid compound name or category. No such compound found.",
                    "error",
                )
                return redirect(url_for("admin_panel"))

            model = row[0]

            cur.execute(
                "DELETE FROM compounds WHERE compound_name = %s AND category = %s",
                (compound_name, category),
            )

            print(f"🛠️ Logging DELETE for compound: {compound_name} ({category})")

            # ✅ Log compound deletion
            log_audit(
                action_type="DELETE",
                actor_email=session.get("admin_email"),
                compound_name=compound_name,
                category=category,
                model=model,
            )

            conn.commit()
            flash("✅ Compound deleted successfully.", "success")

        except Exception as e:
            print("❌ Delete error:", e)
            flash("❌ Error deleting compound.", "error")
        finally:
            cur.close()
            conn.close()

        return redirect(url_for("admin_panel"))

    else:
        flash("❌ Invalid delete type selected.", "error")
        return redirect(url_for("admin_panel"))


@app.route("/update_compound", methods=["POST"])
def update_compound():
    conn = None
    cur = None
    try:
        compound_name = request.form["compound_name"].strip()
        category = request.form["category"].strip()
        density = request.form["density"].strip()
        model = request.form["model"].strip().upper()
        reduced_poly = request.form["reduced_polynomial"].strip()
        # === Validation Starts ===

        # 1. Validate compound name: alphanumeric + underscore
        if not re.match(r"^[A-Za-z0-9_-]+$", compound_name):
            flash(
                "❌ Invalid compound name. Use only letters, digits, or underscores.",
                "error",
            )
            return redirect(url_for("admin_panel"))

        # 2. Validate density (scientific notation)
        if not re.match(r"^\d+(\.\d+)?[eE][-+]?\d+$", density):
            flash(
                "❌ Invalid density format. Use scientific notation like 1.178E-09.",
                "error",
            )
            return redirect(url_for("admin_panel"))

        # 3. Validate model
        if model not in ["HYPERELASTIC", "VISCOELASTIC"]:
            flash(
                "❌ Unsupported model. Choose either 'Hyperelastic' or 'Viscoelastic'.",
                "error",
            )
            return redirect(url_for("admin_panel"))

        # 4. Validate reduced polynomial by N
        coeffs = [c.strip() for c in reduced_poly.split(",")]
        if model == "HYPERELASTIC":
            if len(coeffs) not in [2, 4, 6]:
                flash(
                    "❌ Hyperelastic requires 2 (N=1), 4 (N=2), or 6 (N=3) coefficients.",
                    "error",
                )
                return redirect(url_for("admin_panel"))
        elif model == "VISCOELASTIC":
            if len(coeffs) < 1:
                flash(
                    "❌ Viscoelastic model requires at least one coefficient.",
                    "error",
                )
                return redirect(url_for("admin_panel"))

        # Validate all coefficients are numeric
        for coef in coeffs:
            if not re.match(r"^-?\d+(\.\d+)?$", coef):
                flash(f"❌ Invalid coefficient value: {coef}", "error")
                return redirect(url_for("admin_panel"))

        # === DB Insert or Update ===
        conn = get_db_connection()
        print("✅ Connected to:", conn.dsn)  # Debugging output
        cur = conn.cursor()
        filename = "MANUAL_UPDATE"
        cur.execute(
            """
        INSERT INTO compounds (compound_name, category, density, model, reduced_polynomial, source_file)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (compound_name, category, model)
        DO UPDATE SET 
        density = EXCLUDED.density,
        reduced_polynomial = EXCLUDED.reduced_polynomial,
        source_file = EXCLUDED.source_file
        """,
            (compound_name, category, density, model, reduced_poly, filename),
        )

        # Log only if it was an update

        cur.execute(
            """
                INSERT INTO audit_logs (actor_email, action_type, compound_name, category, model)
                VALUES (%s, 'UPDATE', %s, %s, %s)
                """,
            (session.get("admin_email"), compound_name, category, model),
        )

        conn.commit()
        flash("✅ Compound updated successfully.", "success")

    except Exception as e:
        print("❌ Update error:", e)
        flash("❌ Error updating compound: " + str(e), "error")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return redirect(url_for("admin_panel"))


@app.route("/remove_user_or_admins", methods=["POST"])
def remove_user_or_admins():
    role = request.form["role"]
    email = request.form["email"]

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        if role == "admins":
            cur.execute("SELECT * FROM admins WHERE email = %s", (email,))
            if not cur.fetchone():
                flash("❌ Invalid admin email.", "error")
                return redirect(url_for("admin_panel"))

            cur.execute("DELETE FROM admins WHERE email = %s", (email,))
            flash(f"✅ Admin with email {email} removed successfully.", "success")

        elif role == "user":
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            if not cur.fetchone():
                flash("❌ Invalid user email.", "error")
                return redirect(url_for("admin_panel"))

            cur.execute("DELETE FROM users WHERE email = %s", (email,))
            flash(f"✅ User with email {email} removed successfully.", "success")

        else:
            flash("❌ Invalid role specified.", "error")
            return redirect(url_for("admin_panel"))

        conn.commit()

    except Exception as e:
        print("❌ Remove error:", e)
        flash("❌ Error removing user or admin.", "error")

    finally:
        cur.close()
        conn.close()

    return redirect(url_for("admin_panel"))


@app.route("/routes")
def list_routes():
    import urllib

    output = []
    for rule in app.url_map.iter_rules():
        methods = ",".join(rule.methods)
        line = urllib.parse.unquote(f"{rule.endpoint}: {methods} {rule}")
        output.append(line)
    return "<br>".join(sorted(output))


@app.route("/export_multiple_compounds", methods=["POST"])
def export_multiple_compounds():
    print("✅ Exporting multiple compounds (Admin)")
    data = request.get_json()
    compounds = data.get("compounds", [])

    if not compounds:
        return jsonify({"error": "No compounds provided"}), 400

    lines = []
    conn = get_db_connection()
    cur = conn.cursor()

    for item in compounds:
        name = item.get("compound_name")
        category = item.get("category")
        model = item.get("model", "").upper()

        if not name or not category or not model:
            continue

        cur.execute(
            """
            SELECT density, reduced_polynomial FROM compounds
            WHERE LOWER(compound_name) = LOWER(%s)
              AND LOWER(category) = LOWER(%s)
              AND LOWER(model) = LOWER(%s)
            """,
            (name, category, model),
        )
        row = cur.fetchone()

        if row:
            density, reduced = row
            lines.append(f"*MATERIAL, NAME={name}")
            lines.append("*DENSITY")
            lines.append(f"{density},")
            coeffs = [c.strip() for c in reduced.split(",") if c.strip()]
            N = len(coeffs) // 2

            if model == "HYPERELASTIC":
                lines.append(f"*HYPERELASTIC, REDUCEDPOLYNOMIAL, N = {N}")
                lines.append(",".join(coeffs))
            elif model == "VISCOELASTIC":
                lines.append(f"*VISCOELASTIC, REDUCEDPOLYNOMIAL, N = {N}")
                lines.append(",".join(coeffs))
            else:
                print(f"⚠️ Skipped unsupported model: {model}")
                continue

            lines.append("*" * 84)

    cur.close()
    conn.close()

    if not lines:
        return jsonify({"error": "No valid compound data found"}), 400

    inc_data = "\n".join(lines)
    buffer = io.BytesIO()
    buffer.write(inc_data.encode())
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="admin_compounds.inc",
        mimetype="text/plain",
    )


@app.route("/user_panel")
def user_panel():
    return render_template("user.html")


@app.route("/user_compound_full_data", methods=["POST"])
def user_compound_full_data():
    print("✅ /user_compound_full_data triggered")
    data = request.get_json()
    name = data.get("compound_name")
    category = data.get("category")
    model = data.get("model", "").upper()
    selected_n = data.get("n")

    try:
        selected_n = int(selected_n)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid N value"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT compound_name, category, density, model, reduced_polynomial
        FROM compounds
        WHERE LOWER(compound_name) = LOWER(%s)
          AND LOWER(category) = LOWER(%s)
          AND LOWER(model) = LOWER(%s)
        """,
        (name, category, model),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row:
        reduced = row[4]
        coeffs = [x.strip() for x in reduced.split(",") if x.strip()]
        expected_coeffs = selected_n * 2
        if len(coeffs) == expected_coeffs:
            return jsonify(
                {
                    "compound_name": row[0],
                    "category": row[1],
                    "density": row[2],
                    "model": row[3],
                    "reduced_polynomial": row[4],
                }
            )
        else:
            return (
                jsonify(
                    {
                        "error": "Reduced polynomial data for N={} not found.".format(
                            selected_n
                        )
                    }
                ),
                404,
            )

    return jsonify({"error": "Compound not found"}), 404


@app.route("/user_export_multiple_compounds", methods=["POST"])
def user_export_multiple_compounds():
    print("✅ Exporting user-selected compounds")
    data = request.get_json()
    compounds = data.get("compounds", [])

    if not compounds:
        return jsonify({"error": "No compounds provided"}), 400

    lines = []
    conn = get_db_connection()
    cur = conn.cursor()

    for item in compounds:
        name = item.get("compound_name")
        category = item.get("category")
        model = item.get("model", "").upper()

        if not name or not category or not model:
            continue

        cur.execute(
            """
            SELECT density, reduced_polynomial FROM compounds
            WHERE LOWER(compound_name) = LOWER(%s)
              AND LOWER(category) = LOWER(%s)
              AND LOWER(model) = LOWER(%s)
            """,
            (name, category, model),
        )
        row = cur.fetchone()

        if row:
            density, reduced = row
            lines.append(f"*MATERIAL, NAME={name}")
            lines.append("*DENSITY")
            lines.append(f"{density},")
            if model == "HYPERELASTIC":
                coeffs = reduced.split(",")
                N = len(coeffs) // 2
                lines.append(f"*HYPERELASTIC, REDUCEDPOLYNOMIAL, N = {N}")
                lines.append(reduced)
            elif model == "VISCOELASTIC":
                coeffs = [c.strip() for c in reduced.split(",") if c.strip()]
                N = len(coeffs) // 2
                lines.append(f"*VISCOELASTIC, REDUCEDPOLYNOMIAL, N = {N}")
                lines.append(",".join(coeffs))
            lines.append("*" * 84)

    cur.close()
    conn.close()

    if not lines:
        return jsonify({"error": "No valid compound data found"}), 400

    inc_data = "\n".join(lines)
    buffer = io.BytesIO()
    buffer.write(inc_data.encode())
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="user_compounds.inc",
        mimetype="text/plain",
    )


def log_audit(
    action_type,
    actor_email,
    compound_name=None,
    category=None,
    model=None,
    file_name=None,
):
    print(
        f"🛠️ Logging action: {action_type} by {actor_email} — file: {file_name} — compound: {compound_name}"
    )

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        if action_type in ["UPLOAD", "DELETE_FILE"]:
            cur.execute(
                """
                INSERT INTO audit_logs (actor_email, action_type, file_name, timestamp)
                VALUES (%s, %s, %s, NOW())
                """,
                (actor_email, action_type, file_name),
            )
        elif action_type in ["UPDATE", "DELETE"]:
            cur.execute(
                """
                INSERT INTO audit_logs (actor_email, action_type, compound_name, category, model, file_name, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
                """,
                (actor_email, action_type, compound_name, category, model, file_name),
            )
        conn.commit()
    except Exception as e:
        print("❌ Audit log error:", e)
    finally:
        cur.close()
        conn.close()


@app.route("/view_table/<table>")
def view_table(table):
    allowed_tables = [
        "compounds",
        "audit_logs",
        "login_logs",
        "admins",
        "users",
        "reset_tokens",
        "system_settings",
        "graph_points",
    ]

    # ✅ Validate table name
    if table not in allowed_tables:
        flash("❌ Invalid table requested.", "error")
        return redirect(url_for("admin_panel"))

    try:
        # ✅ Connect to DB
        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Fetch all rows and column names
        cur.execute(f"SELECT * FROM {table}")
        rows = cur.fetchall()
        colnames = [desc[0] for desc in cur.description]

        cur.close()
        conn.close()

        # ✅ Render view_table.html
        return render_template(
            "view_table.html", table_name=table, columns=colnames, rows=rows
        )

    except Exception as e:
        flash(f"❌ Error fetching data from {table}: {str(e)}", "error")
        return redirect(url_for("admin_panel"))


@app.route("/get_graph_data", methods=["POST"])
def get_graph_data():
    data = request.get_json()
    model = data.get("model", "").upper()
    coeffs = data.get("reduced_polynomial", [])

    if not coeffs or not model:
        return jsonify({"error": "Model and coefficients required"}), 400

    try:
        # λ from 1.0 to 2.0 → strain = λ - 1 from 0 to 1
        lambdas = [round(1.0 + x * 0.05, 3) for x in range(21)]  # 1.0 to 2.0
        graph_data = []

        if model == "HYPERELASTIC":
            C10 = float(coeffs[0])
            C20 = float(coeffs[1]) if len(coeffs) > 1 else 0.0
            C30 = float(coeffs[2]) if len(coeffs) > 2 else 0.0

            for λ in lambdas:
                strain = λ - 1  # ✅ strain = λ - 1

                # Term for reduced polynomial
                term = λ**2 + 2 / λ - 3
                stress = (
                    2
                    * ((λ**2) - (1 / λ))
                    * (C10 + 2 * C20 * term + 3 * C30 * (term**2))
                )
                graph_data.append(
                    {"strain": round(strain, 4), "stress": round(stress, 4)}
                )

        elif model == "VISCOELASTIC":
            D1 = float(coeffs[0])
            D2 = float(coeffs[1]) if len(coeffs) > 1 else 0.0
            D3 = float(coeffs[2]) if len(coeffs) > 2 else 0.0

            for strain in [round(x * 0.05, 3) for x in range(21)]:  # 0.0 to 1.0
                stress = D1 * strain + D2 * strain**2 + D3 * strain**3
                graph_data.append(
                    {"strain": round(strain, 4), "stress": round(stress, 4)}
                )

        else:
            return jsonify({"error": "Unsupported model"}), 400

        return jsonify(graph_data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/upload_points_file", methods=["POST"])
def upload_points_file():
    if "admin_email" not in session:
        flash("Unauthorized access", "error")
        return redirect(url_for("admin_login"))

    file = request.files.get("points_file")
    if not file or not file.filename.endswith(".inc"):
        flash("❌ Invalid file. Please upload a .inc points file.", "error")
        return redirect(url_for("admin_panel"))

    lines = file.read().decode("utf-8").splitlines()
    current_compound = None
    data_points = []

    for i, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue

        if re.match(r"^[A-Za-z0-9_-]+$", line):  # New compound block
            current_compound = line
        else:
            if current_compound is None:
                flash(f"❌ No compound name defined before line {i}.", "error")
                return redirect(url_for("admin_panel"))

            try:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) != 2:
                    raise ValueError("Expected two values")
                x, y = float(parts[0]), float(parts[1])
                data_points.append((current_compound, x, y, file.filename))
            except ValueError:
                flash(f"❌ Invalid XY data at line {i}: {line}", "error")
                return redirect(url_for("admin_panel"))

    conn = get_db_connection()
    cur = conn.cursor()
    inserted = updated = 0

    try:
        for compound, x, y, filename in data_points:
            # Check if the point already exists
            cur.execute(
                """
                SELECT y_value FROM graph_points
                WHERE compound_name = %s AND x_value = %s
                """,
                (compound, x)
            )
            result = cur.fetchone()

            if result:
                existing_y = result[0]
                if existing_y != y:
                    # Update y_value if changed
                    cur.execute(
                        """
                        UPDATE graph_points
                        SET y_value = %s, source_file = %s
                        WHERE compound_name = %s AND x_value = %s
                        """,
                        (y, filename, compound, x)
                    )
                    updated += 1
            else:
                # Insert new record
                cur.execute(
                    """
                    INSERT INTO graph_points (compound_name, x_value, y_value, source_file)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (compound, x, y, filename)
                )
                inserted += 1

        conn.commit()
        flash(f"✅ {inserted} new points added. 🔄 {updated} points updated.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"❌ DB error: {e}", "error")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("admin_panel"))

    # ✅ Insert into DB
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        for point in data_points:
            cur.execute(
                "INSERT INTO graph_points (compound_name, x_value, y_value, source_file) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
                point,
            )
        conn.commit()
        flash(f"✅ Uploaded {len(data_points)} points from file.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"❌ DB error: {e}", "error")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("admin_panel"))


@app.route("/get_xy_points", methods=["POST"])
def get_xy_points():
    data = request.get_json()
    compound_name = data.get("compound_name")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT x_value, y_value FROM graph_points WHERE compound_name = %s",
        (compound_name,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    points = [{"x": float(x), "y": float(y)} for x, y in rows]
    return jsonify(points)
@app.route('/clear_all_graph_points', methods=['POST'])
def clear_all_graph_points():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM graph_points")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "✅ All graph points deleted successfully."})

@app.route('/delete_graph_points_by_compound', methods=['POST'])
def delete_graph_points_by_compound():
    data = request.get_json()
    compound_name = data.get("compound_name", "").strip()

    if not compound_name:
        return jsonify({"message": "❌ Compound name required."}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM graph_points WHERE compound_name = %s", (compound_name,))
    count = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()

    if count == 0:
        return jsonify({"message": f"⚠️ No graph points found for '{compound_name}'."})
    else:
        return jsonify({"message": f"✅ Deleted {count} point(s) for '{compound_name}'."})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
