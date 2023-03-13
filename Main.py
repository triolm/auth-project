import sqlite3
from flask import Flask, render_template, request, redirect, flash
from flask_login import LoginManager, login_user, logout_user, current_user
from Auth import create_password_reset_token, get_unlocked_user, lock_user, make_admin, new_user, set_color, set_name, set_password, set_password_without_old_password, unlock_user, unmake_admin, verify_password_reset_token
from Errors import AccountCreationException, AccountModificationException, LoginException
from User import User, lock_expired
# from bson import ObjectId

login_manager = LoginManager()

app = Flask(__name__)
login_manager.init_app(app)

app.config['SECRET_KEY'] = "THIS IS A BAD SECRET KEY"


conn = sqlite3.connect('database.db')
conn.execute(
    'CREATE TABLE IF NOT EXISTS users (name TEXT NOT NULL, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, salt TEXT  NOT NULL, isAdmin SMALL INT, email TEXT NOT NULL, locked SMALLINT, locktime BIGINT,color INT)')
conn.execute(
    'CREATE TABLE IF NOT EXISTS failedlogins (username TEXT  NOT NULL, timestamp BIGINT  NOT NULL)')
conn.execute(
    'CREATE TABLE IF NOT EXISTS passwordreset (username TEXT  NOT NULL, token TEXT NOT NULL, salt NOT NULL, timestamp BIGINT  NOT NULL)')


def is_logged_in():
    if (current_user.is_authenticated):
        if (current_user.locked()):
            lock_user(current_user.get_username())
            logout_user()
            flash("Account locked", "danger")
            return False
    return current_user.is_authenticated


@login_manager.user_loader
def load_user(username):
    print(username)
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if (user != None):
        user = dict(user)
        return User(user)
    return None


@app.route("/")
def index():
    if (not is_logged_in()):
        return redirect("./login")
    return render_template("./home.html", page="home")


@app.route('/login')
def login_page():
    if (is_logged_in()):
        return redirect("./")
    return render_template("./login.html", page="login")


@app.route('/login', methods=['POST'])
def login():
    try:
        user = get_unlocked_user(request.form.get("username"),
                                 request.form.get("password"))
        login_user(user)
        flash("logged in", "success")
        return redirect("./")
    except LoginException as e:
        flash(str(e), "danger")
        return redirect("./login")


@app.route('/signup', methods=["POST"])
def signup():
    try:
        user = new_user(request.form.get("username"),
                        request.form.get("password"),
                        request.form.get("name"),
                        request.form.get("email"),
                        request.form.get("isAdmin"))
        login_user(user)
        flash("Account created", "success")
        return redirect("./")
    except AccountCreationException as e:
        flash(str(e), "danger")
        return redirect("./signup")


@app.route('/signup')
def signup_page():
    if (current_user.is_authenticated):
        return redirect("./")
    return render_template("./signup.html", page="signup")


@app.route("/lock", methods=["POST"])
def lock():
    try:
        if (is_logged_in() and current_user.is_admin()):
            lock_user(request.form.get("username"))
            flash("Account locked", "success")
            return redirect("/manageusers")
    except:
        return redirect("./")
    return redirect("./")


@app.route("/unlock", methods=["POST"])
def unlock():
    if (is_logged_in() and current_user.is_admin()):
        unlock_user(request.form.get("username"))
        flash("Account unlocked", "success")
        return redirect("/manageusers")
    return redirect("./")


@app.route("/promote", methods=["POST"])
def promote():
    if (is_logged_in() and current_user.is_admin()):
        make_admin(request.form.get("username"))
        flash("Admin privledges added", "success")
        return redirect("/manageusers")
    return redirect("./")


@app.route("/demote", methods=["POST"])
def demote():
    if (is_logged_in() and current_user.is_admin()):
        unmake_admin(request.form.get("username"))
        flash("Admin privledges removed", "success")
        return redirect("/manageusers")
    return redirect("./")


@app.route("/settings", methods=["POST"])
def settings():
    if (is_logged_in()):
        if (request.form.get("color")):
            set_color(current_user.get_username(), request.form.get("color"))
        if (request.form.get("name")):
            set_name(current_user.get_username(), request.form.get("name"))
        flash("Settings updated", "success")
        return redirect("/settings")
    return redirect("./")


@app.route("/changepassword", methods=["POST"])
def change_password():
    if (is_logged_in()):
        try:
            set_password(current_user.get_username(),
                         request.form.get("oldpass"), request.form.get("newpass"))
            flash("Settings updated", "success")
        except LoginException:
            flash("Old Password Incorrect", "danger")
        except AccountModificationException:
            flash("Password not strong enough", "danger")
        finally:
            return redirect("/settings")

    elif (request.form.get('username') and request.form.get('token')):
        try:
            if (verify_password_reset_token(request.form.get('token'), request.form.get('username'))):
                set_password_without_old_password(request.form.get('username'),
                                                  request.form.get('password'))
            flash("Password updated", "success")
            return redirect("/login")
        except AccountModificationException:
            flash("Password not strong enough", "danger")
        finally:
            print(request.referrer)
            return redirect(request.referrer)


@app.route("/settings")
def render_settings():
    if (is_logged_in()):
        return render_template("./settings.html")
    return redirect("./")


@app.route("/manageusers")
def manage_users():
    if (is_logged_in() and current_user.is_admin()):

        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        users = conn.execute(
            "SELECT * FROM users")
        users = [dict(row) for row in users.fetchall()]
        conn.close()

        for user in users:
            user.update({"locked": bool(user.get("locked"))})
            if (user.get("locked") == True and lock_expired(user.get("locktime"))):
                unlock_user(user.get("username"))
                user.update({"locked": False})

        return render_template("./manageusers.html", users=users, page="manageusers")
    if is_logged_in():
        return redirect("/")
    return redirect("/login")


@ app.route('/logout')
def logout():
    flash("logged out", "success")
    logout_user()
    return redirect("./")


@app.route("/resetpassword")
def password_reset_page():
    if (request.args.get('token')):
        if ((verify_password_reset_token(request.args.get('token'),
                                         request.args.get('username')))):
            return render_template("./changepassword.html", username=request.args.get('username'), token=request.args.get('token'))
    return render_template("./passwordreset.html")


@app.route("/resetpassword", methods=["POST"])
def password_reset():
    token = create_password_reset_token(request.form.get("username"))
    return token
