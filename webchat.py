#!/usr/bin/env python3
"""
webchat.py - a self-contained, password-protected web chat room.

Anyone with the URL *and* the room password can join.

Secure exposure modes (pick one with --expose):
  local       bind 127.0.0.1 only (testing)
  tailscale   HTTPS inside your tailnet via `tailscale serve`   (default, recommended)
  funnel      public HTTPS URL via `tailscale funnel`           (people NOT on your tailnet)
  cloudflare  public HTTPS URL via a `cloudflared` quick tunnel (no account needed)

In every mode the app itself listens only on 127.0.0.1; the tunnel/VPN provides
TLS, so the password never travels in clear text.

Install:   pip install -r requirements.txt
Run:       python3 webchat.py                      # random password, tailnet only
           python3 webchat.py --expose funnel      # public HTTPS link
           CHAT_PASSWORD='s3cret' python3 webchat.py --expose cloudflare
"""
from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field

try:
    import uvicorn
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse
except ImportError:
    sys.exit('Missing dependencies. Run:  pip install -r requirements.txt')

# ----------------------------------------------------------------------------
# Limits
# ----------------------------------------------------------------------------
MAX_MSG_LEN = 2000          # characters per chat message
MAX_NAME_LEN = 24
HISTORY_SIZE = 100          # messages replayed to new joiners
MSG_RATE = (10, 5.0)        # max 10 messages per 5 s per client
AUTH_TIMEOUT = 15.0         # seconds a socket may stay unauthenticated
FAIL_WINDOW = 60.0          # seconds
FAIL_LIMIT = 10             # failed logins per window (global) before lockout
NAME_RE = re.compile(r"^[\w .\-]{1,%d}$" % MAX_NAME_LEN, re.UNICODE)


# ----------------------------------------------------------------------------
# Chat room state
# ----------------------------------------------------------------------------
@dataclass
class Client:
    ws: WebSocket
    name: str
    sent: deque = field(default_factory=deque)

    def rate_ok(self) -> bool:
        limit, window = MSG_RATE
        now = time.monotonic()
        while self.sent and now - self.sent[0] > window:
            self.sent.popleft()
        if len(self.sent) >= limit:
            return False
        self.sent.append(now)
        return True


class Room:
    def __init__(self, password: str):
        self._pw = password.encode()
        self.clients: set[Client] = set()
        self.history: deque[dict] = deque(maxlen=HISTORY_SIZE)
        self.failures: deque[float] = deque()

    # --- auth ---------------------------------------------------------------
    def locked_out(self) -> bool:
        now = time.monotonic()
        while self.failures and now - self.failures[0] > FAIL_WINDOW:
            self.failures.popleft()
        return len(self.failures) >= FAIL_LIMIT

    def check_password(self, attempt: str) -> bool:
        ok = hmac.compare_digest(attempt.encode(), self._pw)  # constant time
        if not ok:
            self.failures.append(time.monotonic())
        return ok

    def name_taken(self, name: str) -> bool:
        return any(c.name.lower() == name.lower() for c in self.clients)

    # --- messaging ----------------------------------------------------------
    async def broadcast(self, payload: dict, keep: bool = True) -> None:
        if keep:
            self.history.append(payload)
        data = json.dumps(payload)
        dead = []
        for c in list(self.clients):
            try:
                await c.ws.send_text(data)
            except Exception:
                dead.append(c)
        for c in dead:
            self.clients.discard(c)

    async def presence(self) -> None:
        await self.broadcast(
            {"type": "users", "users": sorted(c.name for c in self.clients)}, keep=False
        )


# ----------------------------------------------------------------------------
# Web app
# ----------------------------------------------------------------------------
def build_app(room: Room, title: str) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security_headers(request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self' 'unsafe-inline'; "
            "style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    page = INDEX_HTML.replace("{{TITLE}}", title)

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return page

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        await ws.accept()

        # 1) First frame must be {"type":"auth","password":..,"name":..}
        try:
            raw = await asyncio.wait_for(ws.receive_text(), AUTH_TIMEOUT)
            msg = json.loads(raw)
            password = str(msg.get("password", ""))
            name = " ".join(str(msg.get("name", "")).split())
        except Exception:
            await ws.close(code=1008)
            return

        async def reject(reason: str):
            await ws.send_text(json.dumps({"type": "error", "text": reason}))
            await ws.close(code=1008)

        if room.locked_out():
            return await reject("Too many failed logins. Try again in a minute.")
        if not room.check_password(password):
            await asyncio.sleep(1.5)  # slow down brute force
            return await reject("Wrong password.")
        if not NAME_RE.match(name):
            return await reject(f"Name must be 1-{MAX_NAME_LEN} letters, digits, spaces, . _ -")
        if room.name_taken(name):
            return await reject("That name is already in use.")

        client = Client(ws=ws, name=name)
        room.clients.add(client)
        await ws.send_text(json.dumps({"type": "welcome", "name": name,
                                       "history": list(room.history)}))
        await room.broadcast({"type": "system", "text": f"{name} joined", "ts": time.time()})
        await room.presence()
        print(f"[+] {name} joined ({len(room.clients)} online)")

        # 2) Chat loop
        try:
            while True:
                raw = await ws.receive_text()
                try:
                    text = str(json.loads(raw).get("text", "")).strip()
                except Exception:
                    continue
                if not text:
                    continue
                if len(text) > MAX_MSG_LEN:
                    text = text[:MAX_MSG_LEN]
                if not client.rate_ok():
                    await ws.send_text(json.dumps({"type": "system", "ts": time.time(),
                                                   "text": "Slow down - message dropped."}))
                    continue
                await room.broadcast({"type": "msg", "name": name, "text": text, "ts": time.time()})
        except WebSocketDisconnect:
            pass
        except Exception as e:
            print(f"[!] {name}: {e!r}")
        finally:
            room.clients.discard(client)
            await room.broadcast({"type": "system", "text": f"{name} left", "ts": time.time()})
            await room.presence()
            print(f"[-] {name} left ({len(room.clients)} online)")

    return app


# ----------------------------------------------------------------------------
# Tunnels / VPN exposure
# ----------------------------------------------------------------------------
class Exposure:
    """Starts and tears down the secure front-end for the local server."""

    def __init__(self, mode: str, port: int):
        self.mode, self.port = mode, port
        self.proc: subprocess.Popen | None = None
        self.url: str | None = None

    @staticmethod
    def _need(binary: str, hint: str) -> str:
        path = shutil.which(binary)
        if not path:
            sys.exit(f"'{binary}' not found in PATH. {hint}")
        return path

    def _tailscale_dns(self, ts: str) -> str:
        try:
            out = subprocess.run([ts, "status", "--json"], capture_output=True,
                                 text=True, check=True, timeout=15).stdout
        except subprocess.CalledProcessError as e:
            sys.exit(f"`tailscale status` failed - is tailscaled running and are you logged in?\n{e.stderr}")
        st = json.loads(out)
        if st.get("BackendState") != "Running":
            sys.exit(f"Tailscale is not connected (state: {st.get('BackendState')}). Run `tailscale up`.")
        dns = (st.get("Self") or {}).get("DNSName", "").rstrip(".")
        if not dns:
            sys.exit("Could not determine this machine's Tailscale DNS name (is MagicDNS enabled?).")
        return dns

    def start(self) -> None:
        if self.mode == "local":
            self.url = f"http://127.0.0.1:{self.port}"
            return

        if self.mode in ("tailscale", "funnel"):
            ts = self._need("tailscale", "Install from https://tailscale.com/download")
            dns = self._tailscale_dns(ts)
            sub = "serve" if self.mode == "tailscale" else "funnel"
            # Proxies https://<machine>.<tailnet>.ts.net -> http://127.0.0.1:<port>
            # with an automatically provisioned Let's Encrypt certificate.
            r = subprocess.run([ts, sub, "--bg", "--https=443", f"http://127.0.0.1:{self.port}"],
                               capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                sys.exit(
                    f"`tailscale {sub}` failed:\n{r.stderr or r.stdout}\n"
                    "Tips: enable HTTPS certificates (and Funnel, for --expose funnel) in the "
                    "Tailscale admin console; on Linux you may need `sudo tailscale set --operator=$USER`."
                )
            self.url = f"https://{dns}"
            return

        if self.mode == "cloudflare":
            cf = self._need("cloudflared", "Install from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/")
            self.proc = subprocess.Popen(
                [cf, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{self.port}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
            )
            found = threading.Event()

            def pump():
                for line in self.proc.stderr:  # cloudflared logs the URL to stderr
                    m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", line)
                    if m and not found.is_set():
                        self.url = m.group(0)
                        found.set()

            threading.Thread(target=pump, daemon=True).start()
            if not found.wait(45):
                self.stop()
                sys.exit("Timed out waiting for cloudflared to report a tunnel URL.")

    def stop(self) -> None:
        if self.mode in ("tailscale", "funnel"):
            ts = shutil.which("tailscale")
            sub = "serve" if self.mode == "tailscale" else "funnel"
            if ts:
                subprocess.run([ts, sub, "--https=443", "off"], capture_output=True, timeout=30)
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(description="Password-protected web chat over Tailscale / tunnels.")
    p.add_argument("--expose", choices=["tailscale", "funnel", "cloudflare", "local"],
                   default="tailscale", help="how to securely publish the chat (default: tailscale)")
    p.add_argument("--port", type=int, default=8765, help="local port (default 8765)")
    p.add_argument("--password", help="room password (prefer CHAT_PASSWORD env var; random if unset)")
    p.add_argument("--title", default="Private Chat", help="page title")
    args = p.parse_args()

    password = args.password or os.environ.get("CHAT_PASSWORD") or secrets.token_urlsafe(12)
    if len(password) < 8:
        sys.exit("Password must be at least 8 characters.")
    if args.expose in ("funnel", "cloudflare") and len(password) < 12:
        print("[!] Warning: the URL is public - use a password of 12+ characters.")

    room = Room(password)
    app = build_app(room, args.title)

    exposure = Exposure(args.expose, args.port)
    exposure.start()

    print("\n" + "=" * 60)
    print(f"  Chat URL : {exposure.url}")
    print(f"  Password : {password}")
    print(f"  Mode     : {args.expose}")
    if args.expose == "tailscale":
        print("  (Only devices on your tailnet can reach this URL.)")
    print("  Ctrl+C to stop.")
    print("=" * 60 + "\n")

    # The app never listens on a public interface; the VPN/tunnel terminates TLS.
    config = uvicorn.Config(app, host="127.0.0.1", port=args.port, log_level="warning",
                            proxy_headers=True, forwarded_allow_ips="127.0.0.1",
                            ws_max_size=64 * 1024)
    server = uvicorn.Server(config)
    try:
        server.run()
    finally:
        exposure.stop()
        print("Stopped.")


# ----------------------------------------------------------------------------
# Front-end (single page, no external resources)
# ----------------------------------------------------------------------------
INDEX_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title>
<style>
  :root{--bg:#f6f7f9;--panel:#fff;--fg:#1d2330;--mute:#6b7280;--acc:#2563eb;--line:#e5e7eb}
  @media (prefers-color-scheme:dark){:root{--bg:#0f1115;--panel:#181b22;--fg:#e6e8ee;--mute:#9aa3b2;--acc:#60a5fa;--line:#2a2f3a}}
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.45 system-ui,sans-serif;background:var(--bg);color:var(--fg);height:100dvh;display:flex}
  .center{margin:auto;width:min(360px,92vw);background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:24px}
  h1{font-size:20px;margin:0 0 16px}
  input,button{font:inherit;padding:10px 12px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--fg);width:100%}
  button{background:var(--acc);color:#fff;border:0;cursor:pointer;font-weight:600}
  label{display:block;margin:10px 0 4px;color:var(--mute);font-size:13px}
  .err{color:#dc2626;min-height:1.4em;margin-top:10px;font-size:14px}
  #chat{display:none;flex:1;flex-direction:column;max-width:900px;margin:0 auto;width:100%;padding:0 12px}
  header{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--line);gap:8px;flex-wrap:wrap}
  #users{color:var(--mute);font-size:13px}
  #log{flex:1;overflow-y:auto;padding:12px 0}
  .m{margin:6px 0;word-wrap:break-word;white-space:pre-wrap}
  .m .n{font-weight:600;margin-right:6px}.m .t{color:var(--mute);font-size:12px;margin-right:6px}
  .m.me .n{color:var(--acc)}
  .sys{color:var(--mute);font-style:italic;font-size:13px}
  form#send{display:flex;gap:8px;padding:12px 0 16px;border-top:1px solid var(--line)}
  form#send button{width:auto;padding:10px 18px}
</style></head>
<body>
<div class="center" id="login">
  <h1>{{TITLE}}</h1>
  <form id="lf">
    <label for="name">Your name</label><input id="name" maxlength="24" autocomplete="nickname" required>
    <label for="pw">Room password</label><input id="pw" type="password" autocomplete="current-password" required>
    <div style="height:14px"></div><button>Join</button>
    <div class="err" id="err"></div>
  </form>
</div>
<div id="chat">
  <header><strong>{{TITLE}}</strong><span id="users"></span></header>
  <div id="log"></div>
  <form id="send"><input id="msg" maxlength="2000" autocomplete="off" placeholder="Type a message…"><button>Send</button></form>
</div>
<script>
const $ = id => document.getElementById(id);
let ws, me = null;
const fmt = ts => new Date(ts*1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});

function add(m){
  const log = $('log'), stick = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
  const d = document.createElement('div');
  const t = document.createElement('span'); t.className='t'; t.textContent = fmt(m.ts);
  d.appendChild(t);
  if (m.type === 'msg'){
    d.className = 'm' + (m.name === me ? ' me' : '');
    const n = document.createElement('span'); n.className='n'; n.textContent = m.name;
    d.appendChild(n); d.appendChild(document.createTextNode(m.text));   // textContent only: no XSS
  } else { d.className = 'm sys'; d.appendChild(document.createTextNode(m.text)); }
  log.appendChild(d);
  if (stick) log.scrollTop = log.scrollHeight;
}

$('lf').onsubmit = e => {
  e.preventDefault(); $('err').textContent = '';
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(proto + '//' + location.host + '/ws');
  ws.onopen = () => ws.send(JSON.stringify({type:'auth', name:$('name').value, password:$('pw').value}));
  ws.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if (m.type === 'error'){ $('err').textContent = m.text; return; }
    if (m.type === 'welcome'){
      me = m.name; $('pw').value = '';
      $('login').style.display = 'none'; $('chat').style.display = 'flex';
      m.history.forEach(add); $('msg').focus(); return;
    }
    if (m.type === 'users'){ $('users').textContent = m.users.length + ' online: ' + m.users.join(', '); return; }
    add(m);
  };
  ws.onclose = () => { if (me){ add({type:'system', ts:Date.now()/1000, text:'Disconnected. Reload the page to rejoin.'}); me = null; } };
};

$('send').onsubmit = e => {
  e.preventDefault();
  const v = $('msg').value.trim();
  if (v && ws && ws.readyState === 1){ ws.send(JSON.stringify({text:v})); $('msg').value=''; }
};
</script>
</body></html>
"""

if __name__ == "__main__":
    main()
