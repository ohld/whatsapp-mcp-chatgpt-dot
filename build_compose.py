"""Render docker-compose.yml (bind-mounts ./app.py) and docker-compose.coolify.yml (app.py inlined via Coolify `content:`)."""
import textwrap
app = open("app.py").read()
assert "$" not in app, "Coolify interpolates $ in compose"
body = textwrap.indent(app, " " * 10)


def render(fqdn, app_mount, bridge_ports="", waha_ports=""):
    return f"""services:
  bridge:
    image: python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c
    command: ["python", "-u", "/app/app.py", "serve"]
{bridge_ports}    environment:
{fqdn}      - PUBLIC_URL=${{PUBLIC_URL:?set PUBLIC_URL to the public https origin}}
      - OWNER_NAME=${{OWNER_NAME:-the owner}}
      - OAUTH_REDIRECT_PREFIXES=${{OAUTH_REDIRECT_PREFIXES:-https://chatgpt.com/}}
      - DB_PATH=/data/bridge.db
      - WAHA_URL=http://waha:3000
      - SELF_URL=http://bridge:8080
      - WAHA_SESSION=default
      - OWNER_PASSWORD_SHA256=${{OWNER_PASSWORD_SHA256}}
      - WAHA_API_KEY=${{WAHA_API_KEY}}
      - WAHA_WEBHOOK_HMAC=${{WAHA_WEBHOOK_HMAC}}
      - ALLOWED_CHATS=${{ALLOWED_CHATS:-synthetic:test}}
      - SEND_CHATS=${{SEND_CHATS:-synthetic:test}}
      - SEND_ENABLED=${{SEND_ENABLED:-true}}
      - SEND_NEW_CHATS=${{SEND_NEW_CHATS:-false}}
      - SEND_DAILY_CAP=${{SEND_DAILY_CAP:-30}}
      - RETENTION_DAYS=${{RETENTION_DAYS:-30}}
    volumes:
      - bridge-data:/data
{app_mount}    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health')"]
      interval: 30s
      timeout: 5s
      retries: 3
    depends_on:
      - waha
  waha:
{waha_ports}    image: devlikeapro/waha:gows-2026.10.1@sha256:1f7faeb0227ad5edb5711f7058bfce807ea65e5f92234af0778e4db140f6eb46
    environment:
      - WHATSAPP_DEFAULT_ENGINE=GOWS
      - WAHA_API_KEY=${{WAHA_API_KEY_HASH}}
      - WAHA_DASHBOARD_ENABLED=true
      - WAHA_DASHBOARD_USERNAME=${{WAHA_DASHBOARD_USERNAME:-admin}}
      - WAHA_DASHBOARD_PASSWORD=${{WAHA_DASHBOARD_PASSWORD}}
      - WHATSAPP_SWAGGER_ENABLED=false
      - WAHA_PRINT_QR=false
      - WHATSAPP_RESTART_ALL_SESSIONS=true
      - WHATSAPP_DOWNLOAD_MEDIA=false
      - WAHA_LOG_LEVEL=info
    volumes:
      - waha-sessions:/app/.sessions
      - waha-media:/app/.media
volumes:
  bridge-data:
  waha-sessions:
  waha-media:
"""


open("docker-compose.yml", "w").write(render("", "      - ./app.py:/app/app.py:ro\n",
    "    ports: [\"127.0.0.1:8080:8080\"]  # put an HTTPS reverse proxy in front\n",
    "    ports: [\"127.0.0.1:3000:3000\"]  # WAHA dashboard for QR pairing, via SSH tunnel only\n"))
open("docker-compose.coolify.yml", "w").write(render("      - SERVICE_FQDN_BRIDGE_8080\n",
    f"      - type: bind\n        source: ./app.py\n        target: /app/app.py\n        content: |\n{body}\n"))
print("ok")
