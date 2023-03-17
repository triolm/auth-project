
import os
import time
from AccountDetails import get_user_by_username, hashPassword, sanitise_username
import secrets
import sqlite3

from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

load_dotenv()


def create_password_reset_token(username):
    username = sanitise_username(username)
    # check that user exists
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if (user == None):
        return None
    # invalidate all previous tokens
    expire_password_reset_token(username)
    token = secrets.token_urlsafe(16)
    salt = secrets.token_hex(16)
    hash = hashPassword(token, salt)

    # put token in db
    conn.execute(
        'INSERT INTO passwordreset (username,token,salt,timestamp,used) VALUES (?,?,?,?,0)', (username, hash, salt, time.time()))
    conn.commit()
    conn.close()
    return token


def verify_password_reset_token(token, username):
    # check if username and password reset token match
    username = sanitise_username(username)
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    resettoken = conn.execute(
        "SELECT * FROM passwordreset WHERE username = ? AND used = 0", (username,)).fetchone()
    if (not resettoken):
        return False
    resettoken = dict(resettoken)
    # password reset tokens
    if (bool(resettoken.get("used")) or time.time() - resettoken.get("timestamp") > 60*60):
        return False
    conn.close()
    return resettoken.get("token") == hashPassword(token, resettoken.get("salt"))


def expire_password_reset_token(username):
    conn = sqlite3.connect('database.db')
    conn.execute(
        'UPDATE passwordreset SET used = 1 WHERE username = ? ', (username,))
    conn.commit()
    conn.close()


def send_locked_email(username, url):
    user = get_user_by_username(username)
    if (user == None):
        return
    message = Mail(
        from_email='triolm24+authapp@polyprep.org',
        to_emails=str(user.get_email()),
        subject='Account locked',
        # this email totally looks like a scam
        html_content='''Hello %s, <br> <br> Your Auth App account has been locked for one hour due to failed login attempts.
        You may unlock your account by resetting your password <a href="%s/resetpassword">here</a>.''' % (user.get_name(), url))
    try:
        sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
        response = sg.send(message)
    except Exception as e:
        print(str(e))


def send_password_reset_email(token, email, username, url):
    message = Mail(
        from_email='triolm24+authapp@polyprep.org',
        to_emails=str(email),
        subject='Password Reset Link',
        html_content="To reset your Auth App password please visit the following URL: %sresetpassword?token=%s&username=%s" % (url, token, username))
    try:
        sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
        response = sg.send(message)
    except Exception as e:
        print(str(e))
