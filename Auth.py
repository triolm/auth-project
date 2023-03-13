import hashlib
import secrets
import sqlite3
from Errors import AccountCreationException, AccountModificationException, LoginException
from User import User
import re
import time
import random
import os
from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

load_dotenv()


password_requirements = "(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*(\W)).{10,}"

# what if an account is unlocked, should it require three more attempts to lock
# users should have ids
# routes should be more restful
# make sure conn is always closed and not committed when db wasn't edited


def hashPassword(password, salt):
    salty = password + salt
    return hashlib.sha256(salty.encode()).hexdigest()


def valid_password(password):
    return re.search(password_requirements, password) != None


def new_user(username, password, name, email, isAdmin=False):
    username = username.lower().strip()
    name = name.strip()

    # if (username == password.lower()):
    #     raise AccountCreationException("Username and password cannot be equal")

    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    isAdmin = bool(isAdmin)

    if (not username or username == ""):
        raise AccountCreationException("Please enter a username")

    if (conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()):
        raise AccountCreationException("Username already in use")

    if (not valid_password(password)):
        raise AccountCreationException("Password not strong enough")

    salt = secrets.token_hex(16)

    user = conn.execute(
        'INSERT INTO users(name,username,password,salt, email, isAdmin,locked,locktime,color) VALUES (?,?,?,?,?,?,0,0,?)',
        (name, username, hashPassword(password, salt), salt, email, 1 if isAdmin else 0, random.randint(1, 360)))
    user = dict(conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)).fetchone())
    conn.commit()
    conn.close()

    return User(user)


def set_locked_status(username, status):
    conn = sqlite3.connect('database.db')
    conn.execute(
        'UPDATE users SET locked = ?, locktime = ? WHERE username = ?', (1 if status else 0, time.time(), username))
    conn.commit()
    conn.close()


def lock_user(username):
    set_locked_status(username.lower(), True)


def unlock_user(username):
    set_locked_status(username.lower(), False)


def make_admin(username):
    conn = sqlite3.connect('database.db')
    conn.execute(
        'UPDATE users SET isAdmin = 1 WHERE username = ?', (username,))
    conn.commit()
    conn.close()


def unmake_admin(username):
    conn = sqlite3.connect('database.db')
    conn.execute(
        'UPDATE users SET isAdmin = 0 WHERE username = ?', (username,))
    conn.commit()
    conn.close()


def set_name(username, name):
    conn = sqlite3.connect('database.db')
    conn.execute(
        'UPDATE users SET name = ? WHERE username = ?', (name, username))
    conn.commit()
    conn.close()


def set_password(username, oldpass, newpass):
    user = check_password(username, oldpass)
    set_password_without_old_password(username, newpass)


def set_password_without_old_password(username, password):
    username = username.lower().strip()
    if (not valid_password(password)):
        raise AccountModificationException("Password not strong enough")
    salt = secrets.token_hex(16)
    hashed = hashPassword(password, salt)
    conn = sqlite3.connect('database.db')
    conn.execute(
        'UPDATE users SET salt = ?, password = ? WHERE username = ?', (salt, hashed, username))
    conn.commit()
    conn.close()


def set_color(username, color):
    color = int(color)
    if (not color >= 0 and not color <= 360):
        raise AccountModificationException("Invalid color value")
    conn = sqlite3.connect('database.db')
    conn.execute(
        'UPDATE users SET color = ? WHERE username = ?', (color, username))
    conn.commit()
    conn.close()
    return color


def check_password(username, password):
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if (user == None):
        log_failed_login(username)
        raise LoginException("Username and password do not match")

    conn.close()
    user = dict(user)
    userObj = User(user)

    if (user.get("password") == hashPassword(password, user["salt"])):
        if (userObj.locked() != bool(user.get("locked"))):
            set_locked_status(user.get(username), userObj.locked())
        return userObj
    raise LoginException("Username and password do not match")


def get_user(username, password):
    username = username.lower()

    user = check_password(username, password)
    if (user != None):
        return user

    log_failed_login(username)

    if (fails_over_thresh(username)):
        lock_user(username)
        raise LoginException("Too many failed attempts; Account locked")

    raise LoginException("Username and password do not match")


def log_failed_login(username):
    conn = sqlite3.connect('database.db')
    conn.execute(
        'INSERT INTO failedlogins (username,timestamp) VALUES (?,?)', (username, time.time()))
    conn.commit()
    conn.close()


def fails_over_thresh(username):
    conn = sqlite3.connect('database.db')
    fails = conn.execute(
        'SELECT timestamp FROM failedlogins WHERE username = ? AND timestamp >= ?', (username, time.time() - 60*60))
    nfails = len(fails.fetchall())
    conn.commit()
    conn.close()
    return nfails >= 3


def get_unlocked_user(username, password):
    user = get_user(username, password)
    if (user.locked()):
        raise LoginException("Account locked")
    return user


def create_password_reset_token(username):
    username = username.lower().strip()
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if (user == None):
        return None
    token = secrets.token_urlsafe(16)
    salt = secrets.token_hex(16)
    hash = hashPassword(token, salt)
    conn.execute(
        'INSERT INTO passwordreset (username,token,salt,timestamp) VALUES (?,?,?,?)', (username, hash, salt, time.time()))
    conn.commit()
    conn.close()
    return token


def verify_password_reset_token(token, username):
    username = username.strip().lower()
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    user = conn.execute(
        "SELECT * FROM passwordreset WHERE username = ?", (username,)).fetchone()
    if (not user):
        return False
    user = dict(user)
    conn.close()
    return user.get("token") == hashPassword(token, user.get("salt"))


def send_password_reset_email(token, email):
    message = Mail(
        from_email='triolm24+authapp@polyprep.org',
        to_emails=email + "",
        subject='I am sending an email',
        html_content=token + "")
    try:
        sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e.message)
