import os
import hmac
import secrets
import tempfile
from pathlib import Path
from threading import Lock
from flask import Flask, abort, request, render_template_string, session

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)
app.config.update(SESSION_COOKIE_SAMESITE="Strict", MAX_CONTENT_LENGTH=16_384)
CONFIG_LOCK = Lock()
FIELDS = {"H1_API_USERNAME", "H1_API_TOKEN", "DISCORD_WEBHOOK_URL", "GEMINI_API_KEY",
          "SHODAN_API_KEY", "NOTION_API_KEY", "NOTION_DATABASE_ID", "INTERACTSH_URL",
          "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "TELEGRAM_USER_ID"}

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aegis-Auto Configuration Portal</title>
    <style>

        body {
            margin: 0;
            padding: 0;
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
            color: #fff;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            padding: 40px;
            width: 100%;
            max-width: 600px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            animation: fadeIn 1s ease-in-out;
            margin: 40px 0;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        h1 {
            text-align: center;
            margin-bottom: 10px;
            font-weight: 600;
            background: -webkit-linear-gradient(#00c6ff, #0072ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        p.subtitle {
            text-align: center;
            color: #aaa;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-size: 0.9em;
            color: #ccc;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            background: rgba(0, 0, 0, 0.2);
            color: #fff;
            font-size: 1em;
            outline: none;
            transition: border-color 0.3s, box-shadow 0.3s;
            box-sizing: border-box;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            border-color: #00c6ff;
            box-shadow: 0 0 10px rgba(0, 198, 255, 0.5);
        }
        .btn {
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 8px;
            background: linear-gradient(135deg, #00c6ff, #0072ff);
            color: white;
            font-size: 1.1em;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 114, 255, 0.4);
        }
        .btn:active {
            transform: translateY(0);
        }
        .alert {
            padding: 15px;
            border-radius: 8px;
            background: rgba(46, 213, 115, 0.2);
            border: 1px solid #2ed573;
            color: #2ed573;
            text-align: center;
            margin-bottom: 20px;
            display: {% if success %}block{% else %}none{% endif %};
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Aegis-Auto Portal</h1>
        <p class="subtitle">Configure your DevSecOps Pipeline Secrets</p>
        <div class="alert">✅ Settings saved successfully! The pipeline is ready.</div>
        <form method="POST">
            <input type="hidden" name="csrf" value="{{ csrf }}">
            <p>Fill only the settings you want to change. Blank fields keep their saved values.</p>
            <div class="form-group">
                <label>HackerOne Username</label>
                <input type="text" name="H1_API_USERNAME" placeholder="johndoe">
            </div>
            <div class="form-group">
                <label>HackerOne API Token</label>
                <input type="password" name="H1_API_TOKEN" placeholder="HackerOne API Token">
            </div>
            <div class="form-group">
                <label>Discord Webhook URL</label>
                <input type="password" name="DISCORD_WEBHOOK_URL" placeholder="https://discord.com/api/webhooks/...">
            </div>
            <div class="form-group">
                <label>Gemini API Key (AI Hacker)</label>
                <input type="password" name="GEMINI_API_KEY" placeholder="AIzaSy...">
            </div>
            <div class="form-group">
                <label>Shodan API Key (Origin Hunter)</label>
                <input type="password" name="SHODAN_API_KEY" placeholder="Shodan API Key">
            </div>
            <div class="form-group">
                <label>Notion API Key (Ticketing)</label>
                <input type="password" name="NOTION_API_KEY" placeholder="secret_...">
            </div>
            <div class="form-group">
                <label>Notion Database ID</label>
                <input type="text" name="NOTION_DATABASE_ID" placeholder="Database ID">
            </div>
            <div class="form-group">
                <label>Interactsh URL (OOB Hunter)</label>
                <input type="text" name="INTERACTSH_URL" placeholder="xyz.interact.sh">
            </div>
            <div class="form-group">
                <label>Telegram Bot Token (C2)</label>
                <input type="password" name="TELEGRAM_BOT_TOKEN" placeholder="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11">
            </div>
            <div class="form-group">
                <label>Telegram Chat ID</label>
                <input type="text" name="TELEGRAM_CHAT_ID" placeholder="-100123456789">
            </div>
            <label>Authorized Telegram user ID</label>
            <input type="text" name="TELEGRAM_USER_ID">
            <button type="submit" class="btn">Deploy Configuration 🚀</button>
        </form>
    </div>
</body>
</html>
"""

def save_settings(values):
    """Update only the supplied fields, keeping comments and other settings."""
    path = Path(".env")
    with CONFIG_LOCK:
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        updates = dict(values)
        kept = [line for line in lines if line.partition("=")[0].strip() not in updates]
        kept.extend(f"{key}={value}" for key, value in updates.items())
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".env.", delete=False) as tmp:
            temp_path = Path(tmp.name)
            tmp.write("\n".join(kept) + "\n")
        try:
            temp_path.replace(path)
        finally:
            temp_path.unlink(missing_ok=True)


@app.route("/", methods=["GET", "POST"])
def index():
    expected = os.environ.get("H1_CONFIG_TOKEN", "")
    if not expected:
        abort(503)
    auth = request.authorization
    if not auth or auth.username != "operator" or not hmac.compare_digest(
            (auth.password or "").encode(), expected.encode()):
        return "Operator authentication required", 401, {"WWW-Authenticate": 'Basic realm="H1 configuration"'}
    csrf = session.setdefault("csrf", secrets.token_urlsafe(32))
    if request.method == "POST":
        if not hmac.compare_digest(request.form.get("csrf", "").encode(), csrf.encode()):
            abort(403)
        updates = {k: v for k, v in request.form.items() if k != "csrf" and v}
        if set(updates) - FIELDS or any("\n" in v or "\r" in v or "\x00" in v for v in updates.values()):
            abort(400)
        if updates:
            save_settings(updates)
    return render_template_string(HTML, csrf=csrf, success=request.method == "POST"), 200, {
        "Cache-Control": "no-store", "X-Frame-Options": "DENY"}


if __name__ == "__main__":
    app.run(host=os.environ.get("H1_CONFIG_BIND", "127.0.0.1"), port=5000)
