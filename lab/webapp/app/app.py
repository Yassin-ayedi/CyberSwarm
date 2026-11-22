"""
CyberSwarm target webapp — intentionally weak, for the isolated lab only.

This app is deliberately vulnerable so Blue has something to defend and Red something to
find. It runs ONLY on the internal, no-egress dmz_net. Each weakness below is documented
with the matching fix that Blue's patch_file tool can apply.

Weaknesses (start with #1 only for the MVP; enable more later):
  #1 SQL injection in /login  -> fix: parameterised query (see LOGIN_QUERY_SAFE)
  #2 Path traversal in /download -> fix: os.path.basename + allowlist dir
  #3 Flag readable via SQLi pivot to the `secrets` table
"""
import os
import psycopg2
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

DB = dict(
    host=os.environ.get("DB_HOST", "10.10.3.10"),
    dbname=os.environ.get("DB_NAME", "appdb"),
    user=os.environ.get("DB_USER", "appuser"),
    password=os.environ.get("DB_PASS", "app_pw_change_me"),
)

# Toggle fixes here so Blue's patch is a one-line, reviewable change.
PATCHED_SQLI = os.environ.get("PATCHED_SQLI", "0") == "1"
PATCHED_TRAVERSAL = os.environ.get("PATCHED_TRAVERSAL", "0") == "1"

DOCS_DIR = "/app/docs"


def db():
    return psycopg2.connect(**DB)


@app.route("/")
def index():
    return jsonify(service="acme-portal", status="ok", endpoints=["/login", "/products", "/download"])


@app.route("/products")
def products():
    q = request.args.get("q", "")
    conn = db()
    cur = conn.cursor()
    # Parameterised: this endpoint is safe on purpose, to give traffic-gen normal queries.
    cur.execute("SELECT name, price FROM products WHERE name ILIKE %s", (f"%{q}%",))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(products=[{"name": r[0], "price": float(r[1])} for r in rows])


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("username", "")
    pw = request.form.get("password", "")
    conn = db()
    cur = conn.cursor()
    if PATCHED_SQLI:
        # FIX #1: parameterised query — user input can no longer change the SQL structure.
        cur.execute("SELECT id, username FROM users WHERE username=%s AND password=%s", (user, pw))
    else:
        # WEAKNESS #1: string-built SQL. `' OR '1'='1' -- ` logs in as the first user.
        sql = "SELECT id, username FROM users WHERE username='%s' AND password='%s'" % (user, pw)
        cur.execute(sql)
    row = cur.fetchone()
    cur.close(); conn.close()
    if row:
        return jsonify(ok=True, user=row[1])
    return jsonify(ok=False), 401


@app.route("/download")
def download():
    name = request.args.get("file", "readme.txt")
    if PATCHED_TRAVERSAL:
        # FIX #2: strip any path, serve only from DOCS_DIR.
        name = os.path.basename(name)
    path = os.path.join(DOCS_DIR, name)
    try:
        with open(path, "rb") as f:
            return Response(f.read(), mimetype="application/octet-stream")
    except FileNotFoundError:
        return jsonify(error="not found"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
