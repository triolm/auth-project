import sqlite3

conn = sqlite3.connect('database.db')

conn.row_factory = sqlite3.Row
users = conn.execute("SELECT * FROM passwordreset")
print([dict(row) for row in users.fetchall()])
conn.close()
