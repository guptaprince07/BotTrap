"""BotTrap honeypot (public). Pretends to be an admin portal + API.

Safety: never executes, evaluates or reflects input. Every request is logged
to the DB with status=pending; the pipeline worker classifies it later.
"""
import os
import random
import sys
import time

# Allow running this file directly (python honeypot/app.py): put the repo root
# on sys.path so `honeypot` and `shared` are importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, Response, jsonify, request
from dotenv import load_dotenv

load_dotenv()

from honeypot import fake_pages as fp          # noqa: E402
from honeypot.logger import log_request        # noqa: E402

try:
    from shared.db import init_db
except Exception:  # shared/ not available yet (solo testing)
    def init_db():
        pass

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # refuse bodies > 1 MB

try:
    init_db()
except Exception as exc:  # keep answering even if DB is down; events are just printed
    print(f"[honeypot] init_db failed: {exc}")

ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
LOGIN_PATHS = ["/admin", "/admin/login", "/administrator", "/wp-login.php",
               "/wp-admin", "/login", "/phpmyadmin/"]


@app.before_request
def _log():
    # Log every request except /health (log_request also skips it defensively).
    if request.path != "/health":
        log_request(request)


@app.after_request
def _fake_server_header(resp):
    resp.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/7.4.3"
    return resp


@app.errorhandler(413)
def _too_large(_):
    return Response("Payload Too Large", status=413)


def _delay():
    time.sleep(random.uniform(0.3, 0.8))  # slows brute-force bots, looks like a real backend


def _login_page(path):
    page = fp.PHPMYADMIN_HTML if path.startswith("/phpmyadmin") else fp.LOGIN_HTML
    if request.method == "POST":
        _delay()
        return Response(fp.LOGIN_FAILED_HTML, status=401, mimetype="text/html")
    return Response(page, mimetype="text/html")


# ---- health (not logged) ----
@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ---- bait pages ----
@app.route("/", methods=ALL_METHODS)
def index():
    return Response(fp.LOGIN_HTML, mimetype="text/html")


def _register_login(path):
    def view():
        return _login_page(path)
    view.__name__ = "login_" + path.strip("/").replace("/", "_").replace(".", "_")
    app.add_url_rule(path, view_func=view, methods=ALL_METHODS)


for _p in LOGIN_PATHS:
    _register_login(_p)


@app.route("/api/v1/login", methods=ALL_METHODS)
def api_login():
    if request.method == "POST":
        _delay()
        return jsonify({"error": "Invalid credentials"}), 401
    return jsonify({"error": "Method not allowed", "hint": "POST username and password"}), 405


@app.route("/api/v1/users", methods=ALL_METHODS)
def api_users():
    return jsonify(fp.FAKE_USERS)


@app.route("/api/v1/config", methods=ALL_METHODS)
def api_config():
    return jsonify(fp.FAKE_CONFIG)


@app.route("/.env", methods=ALL_METHODS)
def dot_env():
    return Response(fp.FAKE_ENV, mimetype="text/plain")


@app.route("/.git/config", methods=ALL_METHODS)
def git_config():
    return Response(fp.FAKE_GIT_CONFIG, mimetype="text/plain")


@app.route("/robots.txt", methods=ALL_METHODS)
def robots():
    return Response(fp.ROBOTS_TXT, mimetype="text/plain")


# ---- catch-all: logged by before_request, answered with a generic 404 ----
@app.route("/<path:anything>", methods=ALL_METHODS)
def catch_all(anything):
    return Response(fp.NOT_FOUND_HTML, status=404, mimetype="text/html")


if __name__ == "__main__":
    port = int(os.getenv("PORT", os.getenv("HONEYPOT_PORT", "5000")))
    app.run(host="0.0.0.0", port=port)
