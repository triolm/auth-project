from flask import flash, redirect, render_template, request
from flask_login import current_user, login_user
from AccountDetails import *
from Auth import *
from Errors import *
from PasswordReset import *
from User import lock_expired


def post_login():
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


def post_signup():
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


def post_settings():
    # update color and name of user
    if (request.form.get("color")):
        set_color(current_user.get_username(),
                  request.form.get("color"))
    if (request.form.get("name")):
        set_name(current_user.get_username(), request.form.get("name"))
    flash("Settings updated", "success")
    return redirect("/settings")


def post_change_passwd_not_logged_in():
    # this is a terrible function name
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


def post_change_passwd_logged_in():
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


def passwd_reset_page():
    if (request.args.get('token')):
        # make sure password reset link applies to the given user
        if ((verify_password_reset_token(request.args.get('token'),
                                         request.args.get('username')))):
            return render_template("./changepassword.html", username=request.args.get('username'), token=request.args.get('token'))
    return render_template("./passwordreset.html")


def post_passwd_reset():
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


def failed_logins_page():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    fails = conn.execute(
        "SELECT * FROM failedlogins")
    # cast cursor of fails to dictionary readable by jinja
    fails = [dict(row) for row in fails.fetchall()]
    conn.close()

    return render_template("./failedlogins.html", fails=fails, page="failedlogins")


def manage_users_page():
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
