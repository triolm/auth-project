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
# should a locked account be able to reset their password?
# use the is_active thing
# can password reset allow an insecure password
# admins should be able to see all logins
# the first block is called the genesis block


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


def check_password(username, password):
    username = sanitise_username(username)
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    userObj = None
    # get the details of given username
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if (user != None):
        user = dict(user)
        userObj = User(user)
        # check if hashed inputted password is equal to the hashed password in the db
        if (user.get("password") == hashPassword(password, user["salt"])):
            if (userObj.locked() != bool(user.get("locked"))):
                set_locked_status(user.get(username), userObj.locked())
            return userObj

    log_failed_login(username)

    if (fails_over_thresh(username)):
        lock_user(username)
        raise LoginException("Too many failed attempts; Account locked")
    raise LoginException("Username and password do not match")


def get_user(username, password):
    # i'm aware this method does not do much but it works
    username = sanitise_username(username)
    user = check_password(username, password)
    if (user != None):
        return user


def get_unlocked_user(username, password):
    user = get_user(username, password)
    if (user.locked()):
        raise LoginException("Account locked")
    return user


def set_password_with_auth(username, oldpass, newpass):
    # this will throw an error
    check_password(username, oldpass)
    set_password(username, newpass)
