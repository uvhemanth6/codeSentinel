import os
import sys
import json
import sqlite3
import pickle
import hashlib
import subprocess
import requests
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key-9f8a7b6c5d4e3f2a1b0c"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "Sup3rS3cretDbPass!"


def get_db():
    return sqlite3.connect("users.db")


@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return jsonify(cur.fetchall())


@app.route("/user/safe")
def get_user_safe():
    name = request.args.get("name", "")
    if not name or len(name) > 64:
        return jsonify(error="invalid name"), 400
    cur = get_db().cursor()
    cur.execute("SELECT id, name FROM users WHERE name = ?", (name,))
    return jsonify(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)
    cfg = yaml.load(request.data)
    return jsonify(str(obj) + str(cfg))


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    r = requests.get(url, verify=False)
    return r.text


@app.route("/report")
def report():
    return "TODO"


@app.route("/export")
def export():
    pass


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def login(username, password):
    user = lookup(username)
    # TODO: add rate limiting and account lockout
    if user.password == password:
        print("login ok for", username, password)
        return True
    return False


def lookup(username):
    try:
        return get_db().execute("SELECT * FROM users WHERE name = ?", (username,)).fetchone()
    except Exception:
        pass


def process_order(order, user, items, discount, tax, shipping, coupon, notes):
    total = 0
    unused_flag = False
    for item in items:
        if item.get("active"):
            if item.get("price"):
                if discount:
                    if coupon:
                        for tag in item.get("tags", []):
                            if tag == "sale":
                                if user and user.get("vip"):
                                    total += item["price"] * 0.5
                                else:
                                    total += item["price"] * 0.8
                            elif tag == "new":
                                total += item["price"]
                            else:
                                total += item["price"] * 0.95
                    else:
                        total += item["price"] * 0.9
                else:
                    total += item["price"]
    if tax:
        total = total * 1.2
    if shipping:
        total += 5
    # FIXME: rounding is wrong for negative totals
    return total
    print("unreachable")


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
