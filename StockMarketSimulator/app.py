import os

import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from math import isclose
from datetime import datetime
import pytz

from helpers import login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
con = sqlite3.connect('finance.db', check_same_thread=False)
cur = con.cursor()

os.environ["API_KEY"] = "pk_72a7136f879f4707a306f1e91e7a2932"
# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    total = 0
    portfolio = []
    for row in cur.execute('''SELECT symbol, SUM(shares) FROM transactions
        WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0''', (session["user_id"],)):
        if row[1] > 0:
            info = lookup(row[0])
            stock = {"symbol": row[0], "shares": row[1],
                     "price": info["price"], "total": row[1]*info["price"]}
            total += stock["total"]
            portfolio.append(stock)
    cash_left = cur.execute(
        "SELECT cash FROM users WHERE id = ?", (session["user_id"],)).fetchone()[0]
    return render_template("index.html", stock_list=portfolio, sum=total, cash=cash_left, usd=usd, isclose=isclose)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        if not request.form.get("symbol"):
            return render_template("buy.html", fail="Must provide symbol."), 400
        if not request.form.get("shares", type=int):
            return render_template("buy.html", fail="Must provide shares."), 400
        if request.form.get("shares", type=int) <= 0:
            return render_template("buy.html", fail="Number of shares must be positive."), 400

        stock = lookup(request.form.get("symbol"))
        if not stock:
            return render_template("buy.html", fail="Invalid symbol."), 400
        cost = stock["price"]*request.form.get("shares", type=int)
        cash_left = cur.execute(
            "SELECT cash FROM users WHERE id = ?", (session["user_id"],)).fetchone()[0]
        if cost > cash_left:
            return render_template("buy.html", fail="insufficient funds"), 400

        cur.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                    (session["user_id"], stock["symbol"], request.form.get("shares"), stock["price"]))
        cur.execute("UPDATE users SET cash = ? WHERE id = ?",
                    (cash_left-cost, session["user_id"]))
        con.commit()
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    res = cur.execute(
        "SELECT symbol, shares, price, time FROM transactions WHERE user_id = ? ORDER BY time DESC", (session["user_id"],))
    hist = []
    for row in res:
        tx = {"symbol": row[0], "shares": abs(row[1]), "price": row[2]}
        tx["buy"] = row[1] > 0
        tx_time = datetime.strptime(row[3], "%Y-%m-%d %H:%M:%S")
        utc_time = tx_time.replace(tzinfo=pytz.utc)
        ny_time = utc_time.astimezone(pytz.timezone('America/New_York'))
        tx["time"] = datetime.strftime(ny_time, "%Y-%m-%d %I:%M:%S %p")
        hist.append(tx)
    return render_template("history.html", transactions=hist, usd=usd)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return render_template("login.html", fail="Must provide username."), 403
        if not request.form.get("password"):
            return render_template("login.html", fail="Must provide password."), 403

        rows = cur.execute("SELECT * FROM users WHERE username = ?",
                           (request.form.get("username"),)).fetchall()

        if len(rows) != 1 or not check_password_hash(rows[0][2], request.form.get("password")):
            return render_template("login.html", fail="Username/password incorrect."), 403

        session["user_id"] = rows[0][0]
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return render_template("quote.html", fail="Must provide symbol."), 400

        stock = lookup(request.form.get("symbol"))
        if not stock:
            return render_template("quote.html", fail="Invalid symbol."), 400

        return render_template("quoted.html", info=stock, usd=usd)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        if not request.form.get("username"):
            return render_template("register.html", fail="Must provide username."), 400
        if not request.form.get("password"):
            return render_template("register.html", fail="Must provide password."), 400
        if not request.form.get("confirmation"):
            return render_template("register.html", fail="Must confirm password."), 400
        if request.form.get("password") != request.form.get("confirmation"):
            return render_template("register.html", fail="Passwords do not match."), 400

        rows = cur.execute("SELECT * FROM users WHERE username = ?",
                           (request.form.get("username"),)).fetchall()

        if len(rows) != 0:
            return render_template("register.html", fail="Username already in use."), 400

        cur.execute("INSERT INTO users (username, hash) VALUES (?, ?)", (request.form.get(
            "username"), generate_password_hash(request.form.get("password"))))
        con.commit()

        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    portfolio = cur.execute(
            "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", 
            (session["user_id"],)).fetchall()
    print(portfolio)
    if request.method == "POST":
        if not request.form.get("symbol"):
            print(request.form.get("symbol"))
            return render_template("sell.html", stocks=portfolio, fail="Must provide symbol."), 400
        if not request.form.get("shares", type=int):
            return render_template("sell.html", stocks=portfolio, fail="Must provide positive number of shares."), 400
        if request.form.get("shares", type=int) <= 0:
            return render_template("sell.html", stocks=portfolio, fail="Must provide positive number of shares."), 400

        shares_count = cur.execute("SELECT SUM(shares) FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol",
                                   (session["user_id"], request.form.get("symbol"))).fetchone()[0]
        if shares_count == 0:
            return render_template("sell.html", stocks=portfolio, fail="No shares owned."), 400
        if shares_count < request.form.get("shares", type=int):
            return render_template("sell.html", stocks=portfolio, fail="Cannot sell more shares than owned."), 400

        stock = lookup(request.form.get("symbol"))
        value = stock["price"]*request.form.get("shares", type=int)
        cash_left = cur.execute(
            "SELECT cash FROM users WHERE id = ?", (session["user_id"],)).fetchone()[0]
        cur.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                    (session["user_id"], stock["symbol"], -1*request.form.get("shares", type=int), stock["price"]))
        cur.execute("UPDATE users SET cash = ? WHERE id = ?",
                    (cash_left+value, session["user_id"]))
        con.commit()

        return redirect("/")
    else:
        return render_template("sell.html", stocks=portfolio)
