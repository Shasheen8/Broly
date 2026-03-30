import sqlite3
import subprocess

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE id = " + user_id
    return conn.execute(query).fetchone()

def run_command(cmd):
    return subprocess.call(cmd, shell=True)
