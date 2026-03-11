import sqlite3
import subprocess
import requests

def search_products(query):
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE '%" + query + "%'")
    return cursor.fetchall()

def ping_host(host):
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return result

def fetch_url(user_url):
    response = requests.get(user_url)
    return response.text

def get_config(key):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM config WHERE key = '" + key + "'")
    return cursor.fetchone()
