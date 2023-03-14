
import os
import time
from AccountDetails import hashPassword
import secrets
import sqlite3

from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

load_dotenv()


def create_password_reset_token(username):
    username = username.lower().strip()
    # check that user exists
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if (user == None):
        return None
    expire_password_reset_token(username)
    token = secrets.token_urlsafe(16)
    salt = secrets.token_hex(16)
    hash = hashPassword(token, salt)
    conn.execute(
        'INSERT INTO passwordreset (username,token,salt,timestamp,used) VALUES (?,?,?,?,0)', (username, hash, salt, time.time()))
    conn.commit()
    conn.close()
    return token


def verify_password_reset_token(token, username):
    username = username.strip().lower()
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    resettoken = conn.execute(
        "SELECT * FROM passwordreset WHERE username = ? AND used = 0", (username,)).fetchone()
    if (not resettoken):
        return False
    resettoken = dict(resettoken)
    if (bool(resettoken.get("used")) or time.time() - resettoken.get("timestamp") > 60*60):
        return False
    conn.close()
    print(token)
    return resettoken.get("token") == hashPassword(token, resettoken.get("salt"))


def expire_password_reset_token(username):
    conn = sqlite3.connect('database.db')
    conn.execute(
        'UPDATE passwordreset SET used = 1 WHERE username = ? ', (username,))
    conn.commit()
    conn.close()


def send_password_reset_email(token, email, username, url):
    message = Mail(
        from_email='triolm24+authapp@polyprep.org',
        to_emails=str(email),
        subject='Password Reset Link',
        html_content="To reset your password please visit the following URL: %sresetpassword?token=%s&username=%s" % (url, token, username))
    try:
        sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e.message)
