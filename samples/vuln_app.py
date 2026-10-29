# Deliberately vulnerable code for testing the SAST scanner. DO NOT deploy.
import os, pickle, hashlib, subprocess, yaml, requests

DB_PASSWORD = "SuperSecret123"

def login(cur, user, pw):
    cur.execute("SELECT * FROM users WHERE name='%s' AND pw='%s'" % (user, pw))
    return hashlib.md5(pw.encode()).hexdigest()

def run(cmd):
    os.system("ping " + cmd)
    subprocess.run(cmd, shell=True)

def load(blob, cfg):
    yaml.load(cfg)
    return pickle.loads(blob)

requests.get("https://internal", verify=False)
