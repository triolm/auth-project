
import hashlib
import re
import secrets
import sqlite3
from Errors import *
password_requirements = "(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*(\W)).{10,}"


# mainly setters and validation functions for user database

def hashPassword(password, salt):
    salty = password + salt
    return hashlib.sha256(salty.encode()).hexdigest()


def sanitise_username(username):
    return username.lower().strip()


def valid_password(password):
    return re.search(password_requirements, password) != None


def valid_email(email):
    # email regexes are to complicated
    return True


def make_admin(username):
    conn = sqlite3.connect('database.db')
    conn.execute(
        'UPDATE users SET isAdmin = 1 WHERE username = ?', (username,))
    conn.commit()
    conn.close()


def unmake_admin(username):
    # probably a bad name for this function
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


def set_password(username, password):
    username = username.lower().strip()
    if (not valid_password(password)):
        raise AccountModificationException("Password not strong enough")
    # hash password
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
