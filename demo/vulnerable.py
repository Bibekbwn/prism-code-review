"""DEMO FILE - intentionally vulnerable.

This file exists only to showcase the review tool. Every issue below is
deliberate. Do not copy any of these patterns into real code.
"""

import os
import sqlite3
import subprocess

# SECU-101: hardcoded API key
API_KEY = "sk-test-51H8demoKEYabcdefghij"

# SECU-103: hardcoded password
DB_PASSWORD = "hunter2"


def run_query(user_id):
    conn = sqlite3.connect("app.db")
    # SECU-205: SQL built by string concatenation
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return conn.execute(query).fetchall()


def run_command(filename):
    # SECU-203: shell=True enables command injection
    return subprocess.run("cat " + filename, shell=True, capture_output=True)


def load_config(path):
    # SECU-201: eval on file contents executes arbitrary code
    return eval(open(path).read())


def ping(host):
    return os.system("ping -c 1 " + host)