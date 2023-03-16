import sqlite3
from flask import Flask, render_template, request, redirect, flash
from flask_login import LoginManager, login_user, logout_user, current_user
from AccountDetails import *
from Auth import *
from Locking import *
from PasswordReset import *
from Errors import AccountCreationException, AccountModificationException, LoginException
from User import User, lock_expired
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


@app.route('/login')
def login_page():
    if (is_logged_in()):
        return redirect("./")
    return render_template("./login.html", page="login")


@app.route('/login', methods=['POST'])
def login():
    try:
        # login will throw error if credentials are invalid
        user = get_unlocked_user(request.form.get("username"),
                                 request.form.get("password"))
        login_user(user)
        flash("logged in", "success")
        return redirect("./")
    except LoginException as e:
        flash(str(e), "danger")
        return redirect("./login")


@ app.route('/logout')
def logout():
    if (current_user.is_authenticated):
        flash("logged out", "success")
        logout_user()
    return redirect("./")


@app.route('/signup')
def signup_page():
    if (current_user.is_authenticated):
        return redirect("./")
    return render_template("./signup.html", page="signup")


@app.route('/signup', methods=["POST"])
def signup():
    try:
        # craete new user w/ form data
        user = new_user(request.form.get("username"),
                        request.form.get("password"),
                        request.form.get("name"),
                        request.form.get("email"),
                        request.form.get("isAdmin"))
        # login user
        login_user(user)
        flash("Account created", "success")
        return redirect("./")
    except AccountCreationException as e:
        flash(str(e), "danger")
        return redirect("./signup")


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


@app.route("/settings", methods=["POST"])
def settings():
    if (is_logged_in()):
        # update color and name of user
        if (request.form.get("color")):
            set_color(current_user.get_username(), request.form.get("color"))
        if (request.form.get("name")):
            set_name(current_user.get_username(), request.form.get("name"))
        flash("Settings updated", "success")
        return redirect("/settings")
    return redirect("./")


@app.route("/changepassword", methods=["POST"])
def change_password():
    # if user is changing password while logged in
    if (is_logged_in()):
        try:
            # checks if user inputted correct old password
            set_password_with_auth(current_user.get_username(),
                                   request.form.get("oldpass"), request.form.get("newpass"))
            flash("Settings updated", "success")
        except LoginException:
            flash("Old Password Incorrect", "danger")
        except AccountModificationException:
            flash("Password not strong enough", "danger")
        except Exception as e:
            print(str(e))
        finally:
            return redirect("/settings")

    # if user is changing password from reset link
    elif (request.form.get('username') and request.form.get('token')):
        try:
            if (verify_password_reset_token(request.form.get('token'), request.form.get('username'))):
                expire_password_reset_token(request.form.get('username'))
                # password confrimation
                set_password(request.form.get('username'),
                             request.form.get('password'))
            flash("Password updated", "success")
            return redirect("/login")
        except AccountModificationException as e:
            flash(str(e), "danger")
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
        # cast cursor of users to dictionary readable by jinja
        users = [dict(row) for row in users.fetchall()]
        conn.close()

        for user in users:
            user.update({"locked": bool(user.get("locked"))})
            # make sure users display the correct locked status
            # but this doesn't update the actual DB
            if (user.get("locked") == True and lock_expired(user.get("locktime"))):
                unlock_user(user.get("username"))
                user.update({"locked": False})

        return render_template("./manageusers.html", users=users, page="manageusers")
    if is_logged_in():
        return redirect("/")
    return redirect("/login")


@app.route("/failedlogins")
def failed_logins():
    if (is_logged_in() and current_user.is_admin()):

        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        fails = conn.execute(
            "SELECT * FROM failedlogins")
        # cast cursor of fails to dictionary readable by jinja
        fails = [dict(row) for row in fails.fetchall()]
        conn.close()

        return render_template("./failedlogins.html", fails=fails, page="failedlogins")
    if is_logged_in():
        return redirect("/")
    return redirect("/login")


@app.route("/resetpassword")
def password_reset_page():
    if (request.args.get('token')):
        # make sure password reset link applies to the given user
        if ((verify_password_reset_token(request.args.get('token'),
                                         request.args.get('username')))):
            return render_template("./changepassword.html", username=request.args.get('username'), token=request.args.get('token'))
    return render_template("./passwordreset.html")


@app.route("/resetpassword", methods=["POST"])
def password_reset():
    username = sanitise_username(request.form.get("username"))
    # create token
    token = create_password_reset_token(username)

    # get user object and email the user if the username is valid
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if (user != None):
        user = User(dict(user))
        send_password_reset_email(
            token, user.get_email(), username, request.url_root)
    # claims that it sent the email even if the user doesn't exust
    flash("Email sent", "success")
    return redirect(request.referrer)
