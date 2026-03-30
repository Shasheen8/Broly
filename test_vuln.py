import sqlite3
import os
import subprocess

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE id = " + user_id
    return conn.execute(query).fetchone()

def run_command(cmd):
    return subprocess.call(cmd, shell=True)

def read_file(path):
    with open("/data/" + path) as f:
        return f.read()

API_KEY = "sk-live-abc123def456ghi789"
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"
