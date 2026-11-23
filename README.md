# webchat

A self-contained, password-protected web chat room in a single Python file.
Anyone with the URL **and** the room password can join.

The app only listens on `127.0.0.1`; a VPN or tunnel in front of it provides HTTPS.

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
CHAT_PASSWORD='choose-a-long-password' python3 webchat.py
```

If no password is given, a random one is generated. The URL and password are printed at startup.

| `--expose`  | Who can reach it | How |
|-------------|------------------|-----|
| `tailscale` (default) | Devices on your tailnet | `tailscale serve` (HTTPS, auto certificate) |
| `funnel`    | Anyone with the link | Tailscale Funnel |
| `cloudflare`| Anyone with the link | `cloudflared` quick tunnel (`*.trycloudflare.com`) |
| `local`     | This machine only | testing |

Other options: `--port` (default 8765), `--title`, `--password` (prefer the `CHAT_PASSWORD` env var).

For public modes (`funnel`, `cloudflare`) use a password of 12+ characters.

### Tailscale setup notes

- Enable HTTPS certificates in the Tailscale admin console (and Funnel, for `--expose funnel`).
- On Linux, if `tailscale serve` fails with a permission error: `sudo tailscale set --operator=$USER`.

## Security

- Password sent in the WebSocket's first message (never in the URL), compared in constant time
- Delay on wrong password; global lockout after 10 failures per minute
- Messages rendered as text only (no HTML injection); length and rate limits
- Strict security headers (CSP, no-referrer, no-store)
- History (last 100 messages) is kept in memory only
