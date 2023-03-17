import secrets
import sqlite3

from flask import request
from AccountDetails import *
from Errors import *
from Locking import *
from PasswordReset import send_locked_email
from User import User
import random

# what if an account is unlocked, should it require three more attempts to lock


def new_user(username, password, name, email, isAdmin=False):
    username = sanitise_username(username)
    name = name.strip()

    # hopefully i remembered to uncomment this before i turned the project in
    # if (username == password.lower()):
    #     raise AccountCreationException("Username and password cannot be equal")

    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    isAdmin = bool(isAdmin)

    # make sure name was inputted
    if (name.strip() == ""):
        raise AccountCreationException("Please enter a name")

    if (" " in username):
        raise AccountCreationException("Username may not contain spaces")

    # make sure username is valid
    if (not username or username == ""):
        raise AccountCreationException("Please enter a username")

    # make sure username is not in use
    if (conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()):
        raise AccountCreationException("Username already in use")

    # make sure password is valid
    if (not valid_password(password)):
        raise AccountCreationException("Password not strong enough")

    # make sure email is valid
    if (not valid_email(email)):
        raise AccountCreationException("Email not valid")

    salt = secrets.token_hex(16)

    # write user to db
    user = conn.execute(
        'INSERT INTO users(name,username,password,salt, email, isAdmin,locked,locktime,color) VALUES (?,?,?,?,?,?,0,0,?)',
        (name, username, hashPassword(password, salt), salt, email, 1 if isAdmin else 0, random.randint(1, 360)))
    user = dict(conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)).fetchone())
    conn.commit()
    conn.close()

    return User(user)


def get_user(username, password):
    username = sanitise_username(username)
    user = check_password(username, password)
    if (user != None):
        return user

    log_failed_login(username)

    if (fails_over_thresh(username)):
        user = get_user_by_username(username)
        if (user != None and not bool(user.locked())):
            send_locked_email(username, request.url_root)
        lock_user(username)
        raise LoginException("Too many failed attempts; Account locked")
    raise LoginException("Username and password do not match")


def get_unlocked_user(username, password):
    user = get_user(username, password)
    if (user.locked()):
        raise LoginException("Account locked")
    return user


def set_password_with_auth(username, oldpass, newpass):
    # this will throw an error
    check_password(username, oldpass)
    set_password(username, newpass)
