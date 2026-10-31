#!/usr/bin/env python3
import base64, hashlib, hmac, html, ipaddress, json, os, secrets, socket, threading, time, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unblock import UnblockBackend, UnblockError, normalize_host, currently_open, SUCCESS_MESSAGE

AGH_URL = os.getenv("AGH_URL", "").rstrip("/")
AGH_USERNAME = os.getenv("AGH_USERNAME", "")
AGH_PASSWORD = os.getenv("AGH_PASSWORD", "")
PORT = int(os.getenv("PORT", "80"))
MAX_API_BYTES = 2 * 1024 * 1024
CSRF_KEY = secrets.token_bytes(32)
UNBLOCK_PATH = "/__blockpage/unblock"
ALLOWED_NETWORKS = os.getenv("UNBLOCK_ALLOWED_NETWORKS", "192.168.50.0/24,127.0.0.0/8,::1/128,fc00::/7,fe80::/10")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

def read_api(response):
    raw = response.read(MAX_API_BYTES + 1)
    if len(raw) > MAX_API_BYTES:
        raise ValueError("AdGuard response exceeds the safe size limit")
    return raw

def headers():
    h = {"Accept": "application/json"}
    if AGH_USERNAME:
        token = base64.b64encode(f"{AGH_USERNAME}:{AGH_PASSWORD}".encode()).decode()
        h["Authorization"] = f"Basic {token}"
    return h

def api_get(path, params=None):
    url = AGH_URL + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    with OPENER.open(urllib.request.Request(url, headers=headers()), timeout=3) as r:
        return json.loads(read_api(r).decode())

def api_post(path, payload):
    h = headers()
    h["Content-Type"] = "application/json"
    req = urllib.request.Request(
        AGH_URL + path,
        data=json.dumps(payload).encode(),
        headers=h,
        method="POST",
    )
    with OPENER.open(req, timeout=8) as r:
        raw = read_api(r).strip()
        # set_rules returns an empty body; cache_clear returns plain-text OK.
        if not raw or raw == b"OK":
            return {}
        return json.loads(raw.decode())

BACKEND = UnblockBackend(api_get, api_post, AGH_URL, os.getenv("UNBLOCK_STATE_DIR", "/state"))

def csrf_token(host, client):
    stamp = str(int(time.time()))
    message = (stamp + "\n" + host + "\n" + client).encode()
    return stamp + "." + hmac.new(CSRF_KEY, message, hashlib.sha256).hexdigest()

def valid_token(token, host, client):
    if not isinstance(token, str) or len(token) > 100:
        return False
    try:
        stamp, signature = token.split(".", 1)
        age = time.time() - int(stamp)
        expected = hmac.new(CSRF_KEY, (stamp + "\n" + host + "\n" + client).encode(), hashlib.sha256).hexdigest()
        return -5 <= age <= 600 and hmac.compare_digest(signature, expected)
    except (ValueError, TypeError):
        return False

def client_may_unblock(client):
    try:
        addr = ipaddress.ip_address(client)
        nets = [ipaddress.ip_network(x.strip()) for x in ALLOWED_NETWORKS.split(",") if x.strip()]
        # Include the AI Board's actual on-link global IPv6 networks, not all IPv6.
        proc = Path(os.getenv("UNBLOCK_HOST_PROC", "/host-proc"))
        try:
            raw = (proc / "net/if_inet6").read_text()
            if len(raw) > 65536:
                return False
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) == 6:
                    ip = ipaddress.IPv6Address(int(parts[0], 16))
                    prefix = int(parts[2], 16)
                    if ip.is_global and 48 <= prefix <= 128:
                        nets.append(ipaddress.ip_network((ip, prefix), strict=False))
        except (OSError, ValueError):
            pass
        return any(addr in network for network in nets)
    except ValueError:
        return False

def norm_ip(v):
    v = (v or "").split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(v)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ip)
    except ValueError:
        return v

def is_ip(v):
    try:
        ipaddress.ip_address((v or "").split("%", 1)[0])
        return True
    except ValueError:
        return False


def esc(value):
    return html.escape(str(value), quote=True)


UNBLOCK_JS = r'''
(() => {
  const button = document.getElementById("unblock");
  const refresh = document.getElementById("refresh");
  const feedback = document.getElementById("unblock-feedback");
  if (refresh) refresh.addEventListener("click", () => location.reload());
  if (!button) return;
  button.addEventListener("click", async () => {
    if (button.disabled) return;
    button.disabled = true;
    button.textContent = "Unblocking…";
    feedback.dataset.state = "pending";
    feedback.textContent = "Adding this site to the whitelist. Please wait…";
    try {
      const response = await fetch("/__blockpage/unblock", {
        method: "POST", mode: "same-origin", credentials: "omit", cache: "no-store",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({token: button.dataset.token})
      });
      const result = await response.json();
      feedback.textContent = result.message || "Could not confirm the change. Refresh to check.";
      if (result.ok) {
        document.querySelector("h1.title").textContent = "Unblocked";
        document.querySelector("p.lead").textContent = "AdGuard allows this site. Your device may still have an old DNS result.";
        document.title = "Unblocked";
        feedback.dataset.state = "success";
        button.hidden = true;
        refresh.hidden = false;
        refresh.focus();
      } else if (result.pending) {
        button.textContent = "Waiting for AdGuard";
        refresh.hidden = false;
      } else {
        feedback.dataset.state = "error";
        button.disabled = false;
        button.textContent = "Unblock";
      }
    } catch (_) {
      feedback.dataset.state = "error";
      feedback.textContent = "The result could not be confirmed. Wait, then refresh the page. This request will not be sent again automatically.";
      button.textContent = "Refresh to check";
      refresh.hidden = false;
    }
  });
})();
'''


def is_currently_open(host, client_ip):
    try:
        return currently_open(BACKEND._checks(normalize_host(host), client_ip))
    except (UnblockError, OSError, ValueError, TimeoutError):
        return False


def render_controls(host, client_ip, is_open=False):
    if is_open:
        return ('<div class="unblock-actions"><button id="refresh" type="button">Refresh page</button></div>'
                '<p id="unblock-feedback" class="unblock-feedback" data-state="success" role="status" aria-live="polite">'
                + esc(SUCCESS_MESSAGE) + '</p><script>' + UNBLOCK_JS + '</script>')
    try:
        host = normalize_host(host)
    except UnblockError:
        return ""
    if not client_may_unblock(client_ip):
        return '<p class="note">Unblock is available only from your home network.</p>'
    token = csrf_token(host, client_ip)
    return (
        '<div class="unblock-actions">'
        '<button id="unblock" type="button" data-token="' + esc(token) + '">Unblock</button>'
        '<button id="refresh" type="button" hidden>Refresh page</button></div>'
        '<p class="unblock-footnote">Allows this hostname and its subdomains for every device using this AdGuard.</p>'
        '<p id="unblock-feedback" class="unblock-feedback" role="status" aria-live="polite"></p>'
        '<noscript><p class="note">Enable JavaScript to use Unblock.</p></noscript>'
        '<script>' + UNBLOCK_JS + '</script>'
    )


def process_post(handler):
    status, result = 200, None
    try:
        if handler.path != UNBLOCK_PATH:
            raise UnblockError(404, "This action is unavailable.")
        client_ip = norm_ip(handler.client_address[0])
        if not client_may_unblock(client_ip):
            raise UnblockError(403, "Unblock is available only from your home network.")
        host = normalize_host(handler.request_host())
        if handler.headers.get("Transfer-Encoding"):
            raise UnblockError(400, "Unsupported request body.")
        if handler.headers.get_content_type() != "application/json":
            raise UnblockError(415, "A JSON request is required.")
        lengths = handler.headers.get_all("Content-Length") or []
        if len(lengths) != 1 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= 1024:
            raise UnblockError(413, "Invalid request size.")
        origin = handler.headers.get("Origin")
        if origin:
            parsed = urllib.parse.urlsplit(origin)
            if (parsed.scheme not in ("http", "https") or parsed.username or parsed.password
                    or parsed.path or parsed.query or parsed.fragment
                    or parsed.netloc.lower() != (handler.headers.get("Host") or "").lower()):
                raise UnblockError(403, "Refresh the block page before using Unblock.")
        if handler.headers.get("Sec-Fetch-Site", "same-origin") != "same-origin":
            raise UnblockError(403, "Refresh the block page before using Unblock.")
        payload = json.loads(handler.rfile.read(int(lengths[0])))
        if (not isinstance(payload, dict) or set(payload) != {"token"}
                or not valid_token(payload["token"], host, client_ip)):
            raise UnblockError(403, "This button has expired. Refresh the page and try again.")
        result = BACKEND.run(host, client_ip)
        status = 202 if result.get("pending") else 200
    except UnblockError as exc:
        status, result = exc.status, {"ok": False, "message": exc.message}
    except (ValueError, UnicodeError, TypeError):
        status, result = 400, {"ok": False, "message": "Invalid request. Refresh the block page."}
    except (ConnectionError, TimeoutError, OSError):
        return
    body = json.dumps(result, separators=(",", ":")).encode()
    handler.reply(status, body, "application/json; charset=utf-8")
    try:
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        pass
