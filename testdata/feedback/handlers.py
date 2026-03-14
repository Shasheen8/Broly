import sqlite3
import subprocess
import logging

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()

def run_job(job_name):
    subprocess.check_output("run_job.sh " + job_name, shell=True)
