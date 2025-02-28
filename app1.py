from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from cs50 import SQL
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import timedelta
import re

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///finance.db")

@app.route("/", methods=["GET", "POST"])
@login_required
def dashboard():
    if request.method == "GET":
        balance = db.execute("SELECT balance FROM users WHERE id = ?", session["user_id"])[0]["balance"]
        transactions = db.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC", session["user_id"])
        return render_template("dashboard.html", balance=round(balance, 2), transactions=transactions)

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password are required", "danger")
            return render_template("login.html")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) != 1 or not check_password_hash(rows[0]["password_hash"], password):
            flash("Invalid username or password", "danger")
        else:
            session["user_id"] = rows[0]["id"]
            session.permanent = request.form.get("remember") is not None
            app.permanent_session_lifetime = timedelta(days=30) if session.permanent else timedelta(hours=1)
            flash("Login successful!", "success")
            return redirect("/")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")

        if not username or not password or not email:
            flash("All fields are required!", "danger")
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email format", "danger")
        elif db.execute("SELECT * FROM users WHERE username = ?", username):
            flash("Username already exists", "danger")
        else:
            db.execute("INSERT INTO users (username, email, password_hash, balance) VALUES (?, ?, ?, ?)", username, email, generate_password_hash(password), 0)
            flash("Registration successful! Please log in.", "success")
            return redirect("/login")
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect("/login")

@app.route("/add_transaction", methods=["POST"])
@login_required
def add_transaction():
    try:
        amount = float(request.form.get("amount"))
        category = request.form.get("category")
        type_ = request.form.get("type")

        if type_ == "expense":
            amount *= -1

        db.execute("INSERT INTO transactions (user_id, amount, category, type, date) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)", session["user_id"], amount, category, type_)
        db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", amount, session["user_id"])
        flash("Transaction added successfully!", "success")
    except ValueError:
        flash("Invalid amount entered.", "danger")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")

    return redirect("/")

@app.route("/history", methods=["GET"])
@login_required
def history():
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC", session["user_id"])
    return render_template("history.html", transactions=transactions)

@app.route("/cpw", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        user = db.execute("SELECT password_hash FROM users WHERE id = ?", session["user_id"])[0]

        if not current_password or not new_password or not confirm_password:
            flash("All fields are required.", "danger")
        elif not check_password_hash(user["password_hash"], current_password):
            flash("Incorrect current password!", "danger")
        elif new_password != confirm_password:
            flash("New passwords do not match!", "danger")
        else:
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", generate_password_hash(new_password), session["user_id"])
            flash("Password changed successfully!", "success")
            return redirect("/")
    return render_template("change_password.html")

if __name__ == "__main__":
    app.run(debug=True)