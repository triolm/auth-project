import sqlite3
from flask import Flask, render_template, request, redirect, flash
from flask_login import LoginManager, login_user, logout_user, current_user
from AccountDetails import *
from Auth import *
from Locking import *
from PasswordReset import *
from Errors import AccountCreationException, AccountModificationException, LoginException
from User import User, lock_expired
from Routes import *
# from bson import ObjectId

# cookie manager
login_manager = LoginManager()

app = Flask(__name__)
login_manager.init_app(app)

app.config['SECRET_KEY'] = "THIS IS PROBABLY NOT A VERY GOOD SECRET KEY, BUT I THINK ITS OKAY FOR THE PURPOSES OF THIS PROJECT."

# create SQL tables for users, passwordresets, and failedlogins if they don't already exist
conn = sqlite3.connect('database.db')
conn.execute(
    'CREATE TABLE IF NOT EXISTS users (name TEXT NOT NULL, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, salt TEXT  NOT NULL, isAdmin SMALL INT, email TEXT NOT NULL, locked SMALLINT, locktime BIGINT,color INT)')
conn.execute(
    'CREATE TABLE IF NOT EXISTS failedlogins (username TEXT  NOT NULL, timestamp BIGINT  NOT NULL)')
conn.execute(
    'CREATE TABLE IF NOT EXISTS passwordreset (username TEXT  NOT NULL, token TEXT NOT NULL, salt NOT NULL, timestamp BIGINT  NOT NULL, used SMALLINT)')


# make sure user has a session that is a valid unlocked user
def is_logged_in():
    if (current_user.is_authenticated):
        if (current_user.locked()):
            lock_user(current_user.get_username())
            logout_user()
            flash("Account locked", "danger")
            return False
    return current_user.is_authenticated

# load user, happens on every page load fir a logged in session


@login_manager.user_loader
def load_user(username):
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if (user != None):
        # cast SQL cursor to obj
        user = dict(user)
        return User(user)
    return None


@app.route("/")
def index():
    if (not is_logged_in()):
        return redirect("./login")
    return render_template("./home.html", page="home")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if (is_logged_in()):
        return redirect("./")
    if (request.method == 'POST'):
        return post_login()
    return render_template("./login.html", page="login")


@ app.route('/logout')
def logout():
    if (is_logged_in()):
        flash("logged out", "success")
        logout_user()
    return redirect("./")


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if (is_logged_in()):
        return redirect("./")
    if (request.method == 'POST'):
        return post_signup()
    return render_template("./signup.html", page="signup")


@app.route("/lock", methods=["POST"])
def lock():
    # allow user to lock other accounts only if they are an admin
    if (is_logged_in() and current_user.is_admin()):
        lock_user(request.form.get("username"))
        flash("Account locked", "success")
        return redirect("/manageusers")
    return redirect("./")


@app.route("/unlock", methods=["POST"])
def unlock():
    # allow user to unlock other accounts only if they are an admin
    if (is_logged_in() and current_user.is_admin()):
        unlock_user(request.form.get("username"))
        flash("Account unlocked", "success")
        return redirect("/manageusers")
    return redirect("./")


@app.route("/promote", methods=["POST"])
def promote():
    # allow admins to promote users
    if (is_logged_in() and current_user.is_admin()):
        make_admin(request.form.get("username"))
        flash("Admin privledges added", "success")
        return redirect("/manageusers")
    return redirect("./")


@app.route("/demote", methods=["POST"])
def demote():
    # admins can demote other admins
    if (is_logged_in() and current_user.is_admin()):
        unmake_admin(request.form.get("username"))
        flash("Admin privledges removed", "success")
        return redirect("/manageusers")
    return redirect("./")


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if (request.method == "POST"):
        if (is_logged_in()):
            return post_settings()
        return redirect("./")
    if (is_logged_in()):
        return render_template("./settings.html")
    return redirect("./")


@app.route("/changepassword", methods=["POST"])
def change_password():
    # if user is changing password while logged in
    if (is_logged_in()):
        return post_change_passwd_logged_in()

    # if user is changing password from reset link
    elif (request.form.get('username') and request.form.get('token')):
        return post_change_passwd_not_logged_in()


@app.route("/manageusers")
def manage_users():
    if (is_logged_in() and current_user.is_admin()):
        return manage_users_page()
    if is_logged_in():
        return redirect("/")
    return redirect("/login")


@app.route("/failedlogins")
def failed_logins():
    if (is_logged_in() and current_user.is_admin()):
        return failed_logins_page()
    if is_logged_in():
        return redirect("/")
    return redirect("/login")


@app.route("/resetpassword", methods=["GET", "POST"])
def password_reset():
    if (request.method == "POST"):
        return post_passwd_reset()
    return passwd_reset_page()
