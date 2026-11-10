"""Test file 2: Security issues - secrets and dangerous patterns."""
import os
import subprocess
import pickle
import eval  # This will trigger eval detection

# Hardcoded secrets
API_KEY = "sk-1234567890abcdef1234567890abcdef"
password = "supersecretpassword123"
SECRET_KEY = "my-secret-key-12345"
token = "ghp_1234567890abcdef1234567890abcdef"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

# Dangerous patterns
eval("print('hello')")
exec("x = 1")
os.system("ls -la")
subprocess.call("rm -rf /", shell=True)
pickle.loads(b"malicious data")

def vulnerable_function(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return query