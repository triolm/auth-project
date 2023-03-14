
import sqlite3
import time


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
    conn.close()
    return nfails >= 3
