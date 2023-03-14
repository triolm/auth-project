import secrets
import sqlite3
from AccountDetails import *
from Errors import *
from Locking import *
from User import User
import random

# what if an account is unlocked, should it require three more attempts to lock
# users should have ids
# routes should be more restful
# make sure conn is always closed and not committed when db wasn't edited


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


def get_unlocked_user(username, password):
    user = get_user(username, password)
    if (user.locked()):
        raise LoginException("Account locked")
    return user


def set_password_with_auth(username, oldpass, newpass):
    user = check_password(username, oldpass)
    set_password(username, newpass)
