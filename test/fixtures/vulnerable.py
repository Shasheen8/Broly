"""
Intentionally vulnerable Python file for testing Broly SAST scanning.
DO NOT use any of this code in production.
"""

import sqlite3
import subprocess


def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection: user_id concatenated directly into query
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()


def search_products(keyword):
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    # SQL injection: keyword unsanitized
    cursor.execute("SELECT * FROM products WHERE name LIKE '%" + keyword + "%'")
    return cursor.fetchall()


def read_file(filename):
    # Path traversal: no sanitization on filename
    base_dir = "/var/app/files/"
    with open(base_dir + filename, "r") as f:
        return f.read()


def run_report(report_name):
    # Command injection: subprocess with shell=True and unsanitized input
    subprocess.run("generate_report.sh " + report_name, shell=True)
