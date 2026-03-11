import sqlite3
import subprocess
import os

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()

def run_report(report_name):
    output = subprocess.check_output("generate_report.sh " + report_name, shell=True)
    return output

def read_file(filename):
    base = "/var/app/files/"
    path = base + filename
    with open(path) as f:
        return f.read()

def reset_password(username, new_password):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = '" + new_password + "' WHERE username = '" + username + "'")
    conn.commit()
