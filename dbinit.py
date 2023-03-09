import sqlite3

conn = sqlite3.connect('database.db')

conn.execute(
    'CREATE TABLE IF NOT EXISTS users (name TEXT, username TEXT, password TEXT, salt TEXT, isAdmin SMALL INT,locked SMALLINT, locktime BIGINT)')

conn.row_factory = sqlite3.Row
users = conn.execute("SELECT * FROM users")
print([dict(row) for row in users.fetchall()])
conn.close()
