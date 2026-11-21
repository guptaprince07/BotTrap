"""Fake responses. Everything here is invented; no real data or credentials.
None of these pages ever includes request input (no reflection)."""

from honeypot.tokens import token_for

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Administrator Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:Arial,sans-serif;background:#f1f1f1;display:flex;justify-content:center;padding-top:80px}
form{background:#fff;padding:28px;width:300px;border:1px solid #ddd;box-shadow:0 1px 3px rgba(0,0,0,.1)}
h2{margin-top:0}input{width:100%;padding:8px;margin:6px 0 14px;box-sizing:border-box}
button{background:#2271b1;color:#fff;border:0;padding:10px 16px;cursor:pointer}
small{color:#888}
</style></head><body>
<form method="POST" action="/admin/login">
<h2>Admin Panel</h2>
<label>Username</label><input type="text" name="username" autocomplete="off">
<label>Password</label><input type="password" name="password" autocomplete="off">
<button type="submit">Log In</button>
<p><small>Authorized personnel only.</small></p>
</form></body></html>"""

LOGIN_FAILED_HTML = """<!DOCTYPE html><html><head><title>Login failed</title></head>
<body style="font-family:Arial,sans-serif;text-align:center;padding-top:80px">
<h3>401 - Invalid credentials</h3><p><a href="/admin">Try again</a></p></body></html>"""

PHPMYADMIN_HTML = """<!DOCTYPE html><html><head><title>phpMyAdmin</title></head>
<body style="font-family:Arial,sans-serif;background:#eef;display:flex;justify-content:center;padding-top:80px">
<form method="POST" action="/phpmyadmin/" style="background:#fff;padding:24px;width:300px;border:1px solid #99a">
<h3>Welcome to phpMyAdmin</h3>
<label>Username</label><input name="pma_username" style="width:100%;margin:6px 0 12px">
<label>Password</label><input type="password" name="pma_password" style="width:100%;margin:6px 0 12px">
<button type="submit">Go</button></form></body></html>"""

NOT_FOUND_HTML = """<html>
<head><title>404 Not Found</title></head>
<body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body>
</html>"""

# Static fallbacks kept intact so existing imports do not break during migration
FAKE_USERS = {
    "users": [
        {"id": 1, "username": "admin", "email": "admin@example.test", "role": "administrator"},
        {"id": 2, "username": "jdoe", "email": "jdoe@example.test", "role": "editor"},
        {"id": 3, "username": "svc_backup", "email": "backup@example.test", "role": "service"},
    ],
    "total": 3,
}

FAKE_CONFIG = {
    "app": "internal-portal",
    "version": "2.4.1",
    "debug": True,
    "db_host": "db.internal.example.test",
    "api_key": "FAKE-0000-NOT-A-REAL-KEY",
}

FAKE_ENV = """APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0=
DB_CONNECTION=mysql
DB_HOST=10.0.0.5
DB_PORT=3306
DB_DATABASE=portal
DB_USERNAME=portal_user
DB_PASSWORD=NotARealPassword123
AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKE0000
AWS_SECRET_ACCESS_KEY=fakefakefakefakefakefakefakefakefake0000
"""

FAKE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = https://git.example.test/internal/portal.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

# Bait: "disallowing" these paths invites crawlers to look at them.
ROBOTS_TXT = """User-agent: *
Disallow: /admin
Disallow: /backup
Disallow: /.git/
Disallow: /api/v1/config
"""


# --- Per-visitor honey-token page generators ---

def fake_users(ip: str, ua: str = "") -> dict:
    return {
        "users": [
            {
                "id": 1,
                "username": "admin",
                "email": "admin@example.test",
                "role": "administrator",
                "api_token": token_for(ip, "/api/v1/users", "api_key", ua),
            },
            {"id": 2, "username": "jdoe", "email": "jdoe@example.test", "role": "editor"},
            {"id": 3, "username": "svc_backup", "email": "backup@example.test", "role": "service"},
        ],
        "total": 3,
    }


def fake_config(ip: str, ua: str = "") -> dict:
    return {
        "app": "internal-portal",
        "version": "2.4.1",
        "debug": True,
        "db_host": "db.internal.example.test",
        "api_key": token_for(ip, "/api/v1/config", "api_key", ua),
    }


def fake_env(ip: str, ua: str = "") -> str:
    return (
        "APP_ENV=production\n"
        "APP_DEBUG=false\n"
        "APP_KEY=base64:FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0=\n"
        "DB_CONNECTION=mysql\n"
        "DB_HOST=10.0.0.5\n"
        "DB_PORT=3306\n"
        "DB_DATABASE=portal\n"
        "DB_USERNAME=portal_user\n"
        f"DB_PASSWORD={token_for(ip, '/.env', 'password', ua)}\n"
        f"ADMIN_KEY={token_for(ip, '/.env', 'api_key', ua)}\n"
        "AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKE0000\n"
        "AWS_SECRET_ACCESS_KEY=fakefakefakefakefakefakefakefakefake0000\n"
    )


def fake_git_config(ip: str, ua: str = "") -> str:
    git_password = token_for(ip, "/.git/config", "password", ua)
    return (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        '[remote "origin"]\n'
        f"\turl = https://deploy:{git_password}@git.example.test/internal/portal.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        '[branch "main"]\n'
        "\tremote = origin\n"
        "\tmerge = refs/heads/main\n"
    )
