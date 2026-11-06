"""Deliberately vulnerable Flask-style handler, for taint-tracking tests. DO NOT deploy."""
from flask import request
import os


def run_ping():
    host = request.args.get("host")
    os.system("ping " + host)           # PY-CMD-001, should be 'source' tier (HIGH, confirmed)


def run_ping_constant():
    os.system("ping 127.0.0.1")         # pure constant: should NOT be flagged at all
