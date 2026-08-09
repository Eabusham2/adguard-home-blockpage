#!/usr/bin/env python3
import base64
import html
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AGH_URL = os.getenv("AGH_URL", "").rstrip("/")
AGH_USERNAME = os.getenv("AGH_USERNAME", "")
AGH_PASSWORD = os.getenv("AGH_PASSWORD", "")
PORT = int(os.getenv("PORT", "80"))

FRIENDLY_REASONS = {
    "FilteredBlackList": "DNS blocklist",
    "FilteredSafeBrowsing": "Safe Browsing",
    "FilteredParental": "Parental controls",
    "FilteredInvalid": "Invalid destination",
    "FilteredSafeSearch": "Safe Search",
    "FilteredBlockedService": "Blocked service",
    "Rewrite": "DNS rewrite",
    "RewriteEtcHosts": "Hosts-file rewrite",
    "RewriteRule": "DNS rewrite rule",
    "NotFilteredWhiteList": "Allowlist exception",
}
SPECIAL_LISTS = {
    "0": "Custom filtering rules",
    "-1": "System hosts file",
    "-2": "Blocked services",
    "-3": "Parental controls",
    "-4": "Safe Browsing",
    "-5": "Safe Search",
}
CACHE = {
    "filters_until": 0.0,
    "filters": {},
    "clients_until": 0.0,
    "clients": [],
}


def auth_headers():
    headers = {"Accept": "application/json"}
    if AGH_USERNAME:
        token = base64.b64encode(f"{AGH_USERNAME}:{AGH_PASSWORD}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    return headers


def api_get(path, params=None):
    url = AGH_URL + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=auth_headers())
    with urllib.request.urlopen(req, timeout=3) as response:
        return json.loads(response.read().decode())


def api_post(path, payload):
    headers = auth_headers()
    headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        AGH_URL + path,
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=3) as response:
        return json.loads(response.read().decode())


def normalize_ip(value):
    value = (value or "").strip().split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(value)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(addr)
    except ValueError:
        return value


def is_ip(value):
    try:
        ipaddress.ip_address((value or "").split("%", 1)[0])
        return True
    except ValueError:
        return False


def filter_names():
    now = time.time()
    if CACHE["filters_until"] > now:
        return CACHE["filters"]

    names = dict(SPECIAL_LISTS)
    try:
        status = api_get("/control/filtering/status")
        for section in ("filters", "whitelist_filters"):
            for item in status.get(section, []) or []:
                filter_id = item.get("id")
                name = item.get("name")
                if filter_id is not None and name:
                    names[str(filter_id)] = str(name)
    except Exception:
        pass

    CACHE["filters"] = names
    CACHE["filters_until"] = now + 300
    return names


def client_catalog():
    now = time.time()
    if CACHE["clients_until"] > now:
        return CACHE["clients"]

    catalog = []
    try:
        data = api_get("/control/clients")
        for item in data.get("clients", []) or []:
            name = str(item.get("name") or "").strip()
            ids = [str(x).strip() for x in item.get("ids", []) or [] if str(x).strip()]
            ip_addrs = [normalize_ip(str(x)) for x in item.get("ip_addrs", []) or [] if str(x).strip()]
            catalog.append({"name": name, "ids": ids, "ip_addrs": ip_addrs})

        for item in data.get("auto_clients", []) or []:
            ip = normalize_ip(str(item.get("ip") or ""))
            name = str(item.get("name") or "").strip()
            if ip or name:
                catalog.append({"name": name, "ids": [ip] if ip else [], "ip_addrs": [ip] if ip else []})
    except Exception:
        pass

    CACHE["clients"] = catalog
    CACHE["clients_until"] = now + 120
    return catalog


def address_set(client):
    out = []
    for value in list(client.get("ip_addrs", [])) + list(client.get("ids", [])):
        value = normalize_ip(str(value))
        if is_ip(value) and value not in out:
            out.append(value)
    return out


def normalize_mac(value):
    value = str(value or "").strip().lower().replace("-", ":")
    if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value):
        return value
    return ""


def mac_ids(client):
    out = []
    for value in client.get("ids", []) or []:
        mac = normalize_mac(value)
        if mac and mac not in out:
            out.append(mac)
    return out


def neighbor_entries():
    found = []
    seen = set()
    for command in (["ip", "neigh", "show"], ["ip", "-6", "neigh", "show"]):
        try:
            output = subprocess.check_output(command, stderr=subprocess.DEVNULL, text=True, timeout=1.5)
        except Exception:
            continue
        for line in output.splitlines():
            parts = line.split()
            if not parts:
                continue
            addr = normalize_ip(parts[0])
            try:
                idx = parts.index("lladdr")
                mac = normalize_mac(parts[idx + 1])
            except (ValueError, IndexError):
                mac = ""
            if is_ip(addr) and mac and (addr, mac) not in seen:
                seen.add((addr, mac))
                found.append((addr, mac))

    try:
        with open("/proc/net/arp", "r", encoding="utf-8", errors="ignore") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                addr = normalize_ip(parts[0])
                mac = normalize_mac(parts[3])
                if is_ip(addr) and mac and mac != "00:00:00:00:00:00" and (addr, mac) not in seen:
                    seen.add((addr, mac))
                    found.append((addr, mac))
    except Exception:
        pass
    return found


def find_client_by_ip(client_ip):
    client_ip = normalize_ip(client_ip)
    for client in client_catalog():
        values = {normalize_ip(x) for x in client.get("ip_addrs", [])}
        values.update(normalize_ip(x) for x in client.get("ids", []) if is_ip(str(x)))
        if client_ip in values:
            return client
    return None


def find_client_by_name(name):
    if not name:
        return None
    target = name.casefold().rstrip(".")
    for client in client_catalog():
        candidate = str(client.get("name") or "").casefold().rstrip(".")
        if candidate and candidate == target:
            return client
    return None


def name_from_clients_search(client_ip):
    try:
        data = api_post("/control/clients/search", {"clients": [{"id": client_ip}]})
    except Exception:
        return ""

    def walk(value):
        if isinstance(value, dict):
            if str(value.get("name") or "").strip():
                return str(value["name"]).strip()
            for nested in value.values():
                found = walk(nested)
                if found:
                    return found
        elif isinstance(value, list):
            for nested in value:
                found = walk(nested)
                if found:
                    return found
        return ""

    return walk(data)


def name_from_querylog(client_ip):
    try:
        data = api_get("/control/querylog", {"search": client_ip, "limit": 50})
    except Exception:
        return ""

    entries = data.get("data", []) if isinstance(data, dict) else []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        logged_ip = normalize_ip(str(entry.get("client") or ""))
        if logged_ip and logged_ip != client_ip:
            continue
        info = entry.get("client_info")
        if isinstance(info, dict):
            name = str(info.get("name") or "").strip()
            if name:
                return name
        name = str(entry.get("client_name") or "").strip()
        if name:
            return name
    return ""


def device_info(client_ip):
    client_ip = normalize_ip(client_ip)
    info = {"name": "", "current": client_ip, "addresses": [], "macs": []}

    def add_address(value):
        value = normalize_ip(value)
        if is_ip(value) and value not in info["addresses"]:
            info["addresses"].append(value)

    def add_mac(value):
        value = normalize_mac(value)
        if value and value not in info["macs"]:
            info["macs"].append(value)

    def absorb_client(client):
        if not client:
            return False
        changed = False
        name = str(client.get("name") or "").strip()
        if name and not info["name"]:
            info["name"] = name
            changed = True
        before_a, before_m = len(info["addresses"]), len(info["macs"])
        for address in address_set(client):
            add_address(address)
        for mac in mac_ids(client):
            add_mac(mac)
        return changed or len(info["addresses"]) != before_a or len(info["macs"]) != before_m

    def absorb_neighbors(neighbors):
        changed = False
        known_macs = set(info["macs"])
        for addr, mac in neighbors:
            if addr in info["addresses"] and mac not in known_macs:
                add_mac(mac)
                known_macs.add(mac)
                changed = True
        for addr, mac in neighbors:
            if mac in known_macs and addr not in info["addresses"]:
                add_address(addr)
                changed = True
        return changed

    add_address(client_ip)
    neighbors = neighbor_entries()

    for _ in range(4):
        changed = False
        for address in list(info["addresses"]):
            if absorb_client(find_client_by_ip(address)):
                changed = True
        if absorb_neighbors(neighbors):
            changed = True
        if not changed:
            break

    if not info["name"]:
        for address in list(info["addresses"]):
            name = name_from_clients_search(address) or name_from_querylog(address)
            if name:
                info["name"] = name
                break

    if info["name"]:
        absorb_client(find_client_by_name(info["name"]))
        absorb_neighbors(neighbors)
        for address in list(info["addresses"]):
            absorb_client(find_client_by_ip(address))

    if not info["name"]:
        for address in list(info["addresses"]):
            try:
                host = socket.gethostbyaddr(address)[0].rstrip(".")
                if host and host != address:
                    info["name"] = host
                    break
            except Exception:
                pass

    return info


def check_host(host, client_ip, qtype):
    try:
        data = api_get(
            "/control/filtering/check_host",
            {"name": host, "client": client_ip, "qtype": qtype},
        )
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def merge_types(existing, qtype):
    if qtype not in existing:
        existing.append(qtype)


def rule_kind(text):
    text = str(text or "").strip()
    lower = text.lower()
    if not text:
        return "Rule"
    if "$dnsrewrite" in lower:
        if re.search(r"(?:^|[;,])\s*cname\s*(?:[;,]|$)", lower):
            return "CNAME rewrite"
        return "DNS rewrite"
    if len(text) >= 2 and text.startswith("/") and text.rfind("/") > 0:
        return "Regex"
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}\s+\S+", text) or re.match(r"^[0-9a-fA-F:]+\s+\S+", text):
        return "Hosts"
    if "*" in text:
        return "Wildcard"
    if re.fullmatch(r"(?:@@)?\|\|[^*^/$|]+\^", text):
        return "Domain"
    if text.startswith("||") or text.startswith("@@") or any(ch in text for ch in "^$|"):
        return "Adblock"
    if re.fullmatch(r"[A-Za-z0-9_.-]+", text):
        return "Exact"
    return "Rule"


def block_details(host, client_ip):
    names = filter_names()
    reasons = {}
    rules = {}
    services = {}
    cnames = {}
    rewrites = {}
    api_ok = False

    for qtype in ("A", "AAAA"):
        data = check_host(host, client_ip, qtype)
        if data:
            api_ok = True

        raw_reason = str(data.get("reason") or "").strip()
        if raw_reason:
            item = reasons.setdefault(
                raw_reason,
                {"raw": raw_reason, "friendly": FRIENDLY_REASONS.get(raw_reason, raw_reason), "types": []},
            )
            merge_types(item["types"], qtype)

        service = str(data.get("service_name") or "").strip()
        if service:
            item = services.setdefault(service, {"value": service, "types": []})
            merge_types(item["types"], qtype)

        cname = str(data.get("cname") or "").strip()
        if cname:
            item = cnames.setdefault(cname, {"value": cname, "types": []})
            merge_types(item["types"], qtype)

        for address in data.get("ip_addrs", []) or []:
            address = normalize_ip(str(address))
            if address:
                item = rewrites.setdefault(address, {"value": address, "types": []})
                merge_types(item["types"], qtype)

        matched = data.get("rules") or []
        if not matched and data.get("rule"):
            matched = [{"text": data.get("rule"), "filter_list_id": data.get("filter_id")}]

        for rule in matched:
            if isinstance(rule, str):
                text, filter_id = rule, None
            elif isinstance(rule, dict):
                text = str(rule.get("text") or rule.get("rule") or "").strip()
                filter_id = rule.get("filter_list_id", rule.get("filter_id"))
            else:
                continue

            list_name = ""
            if filter_id is not None:
                list_name = names.get(str(filter_id), f"Filter #{filter_id}")

            key = (list_name, text)
            item = rules.setdefault(key, {"list": list_name, "rule": text, "kind": rule_kind(text), "types": []})
            merge_types(item["types"], qtype)

    if not reasons:
        reasons[""] = {"raw": "", "friendly": "Network filtering", "types": []}

    return {
        "reasons": list(reasons.values()),
        "rules": list(rules.values()),
        "services": list(services.values()),
        "cnames": list(cnames.values()),
        "rewrites": list(rewrites.values()),
        "api_ok": api_ok,
    }


def esc(value):
    return html.escape(str(value), quote=True)


CSS = r'''
:root{color-scheme:light dark;--bg:#fff;--text:#181818;--muted:#6d6d6d;--line:#e2e2e2;--soft:#f6f6f6;--accent:#a12620;--chip:#eeeeec}
@media(prefers-color-scheme:dark){:root{--bg:#171717;--text:#f1f1f1;--muted:#aaa;--line:#383838;--soft:#222;--accent:#ff9189;--chip:#2a2a29}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{width:min(700px,100%);margin:0 auto;padding:max(38px,env(safe-area-inset-top)) max(20px,env(safe-area-inset-right)) max(44px,env(safe-area-inset-bottom)) max(20px,env(safe-area-inset-left))}
header{padding-bottom:24px}.eyebrow{margin:0 0 6px;color:var(--accent);font-size:13px;font-weight:650}.title{margin:0;font-size:30px;line-height:1.15;letter-spacing:-.02em}.lead{margin:8px 0 0;color:var(--muted);max-width:56ch}.domain{margin-top:20px;padding:12px 14px;background:var(--soft);border-radius:7px;font:600 17px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
section{margin-top:26px}.section-title{margin:0 0 9px;font-size:15px;font-weight:650}.panel{border-top:1px solid var(--line)}.row{display:grid;grid-template-columns:112px minmax(0,1fr);gap:18px;padding:10px 0;border-bottom:1px solid var(--line)}.label{color:var(--muted)}.value{min-width:0;overflow-wrap:anywhere}.value strong{font-weight:620}.mono{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.rule{padding:14px 0;border-top:1px solid var(--line)}.rule:first-child{border-top:0}.rulehead{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.filter{font-weight:620}.chip{display:inline-block;padding:2px 7px;border-radius:999px;background:var(--chip);color:var(--muted);font-size:11px;line-height:1.5}.ruletext{margin-top:7px;font:12.5px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere;color:var(--muted)}
.dns-grid{border-top:1px solid var(--line)}details{margin-top:27px;border-top:1px solid var(--line);padding-top:12px}summary{color:var(--muted);cursor:pointer;user-select:none}.technical{margin-top:9px;color:var(--muted);font-size:13px}.technical div{margin:4px 0}.note{margin-top:22px;color:var(--muted);font-size:13px}.status{min-height:70dvh;display:grid;align-content:center}
@media(max-width:520px){main{padding-left:15px;padding-right:15px}.title{font-size:27px}.row{grid-template-columns:1fr;gap:2px;padding:9px 0}.domain{font-size:15px}.rulehead{align-items:flex-start}.chip{margin-top:1px}}
'''

def types_text(types):
    return " + ".join(types)


def render_status(host):
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark"><title>Block page</title><style>{CSS}</style></head><body><main class="status"><header><p class="eyebrow">Block page</p><h1 class="title">Service is running</h1><p class="lead">AdGuard Home can redirect blocked HTTP destinations to this address.</p><div class="domain">{esc(host)}</div></header></main></body></html>'''.encode()


def render_blocked(host, device, details):
    ipv4 = [a for a in device.get("addresses", []) if ":" not in a]
    ipv6 = [a for a in device.get("addresses", []) if ":" in a]

    device_rows = []
    if device.get("name"):
        device_rows.append(f'<div class="row"><div class="label">Name</div><div class="value"><strong>{esc(device["name"])}</strong></div></div>')
    if ipv4:
        device_rows.append(f'<div class="row"><div class="label">IPv4</div><div class="value mono">{esc(", ".join(ipv4))}</div></div>')
    if ipv6:
        device_rows.append(f'<div class="row"><div class="label">IPv6</div><div class="value mono">{esc(", ".join(ipv6))}</div></div>')
    if device.get("macs"):
        device_rows.append(f'<div class="row"><div class="label">MAC</div><div class="value mono">{esc(", ".join(device["macs"]))}</div></div>')
    device_html = f'<section><h2 class="section-title">Device details</h2><div class="panel">{"".join(device_rows)}</div></section>' if device_rows else ""

    why_items = []
    if details["rules"]:
        for item in details["rules"]:
            source = esc(item["list"] or "Filtering rule")
            chips = [item.get("kind", "Rule")]
            qtypes = types_text(item["types"])
            if qtypes:
                chips.append(qtypes)
            chip_html = "".join(f'<span class="chip">{esc(x)}</span>' for x in chips if x)
            text = esc(item["rule"] or "Rule text unavailable")
            why_items.append(f'<div class="rule"><div class="rulehead"><span class="filter">{source}</span>{chip_html}</div><div class="ruletext">{text}</div></div>')
    elif details["services"]:
        for item in details["services"]:
            qtypes = types_text(item["types"])
            chip = f'<span class="chip">{esc(qtypes)}</span>' if qtypes else ""
            why_items.append(f'<div class="rule"><div class="rulehead"><span class="filter">Blocked service: {esc(item["value"])}</span>{chip}</div></div>')
    else:
        reason = details["reasons"][0]
        qtypes = types_text(reason["types"])
        chip = f'<span class="chip">{esc(qtypes)}</span>' if qtypes else ""
        why_items.append(f'<div class="rule"><div class="rulehead"><span class="filter">{esc(reason["friendly"])}</span>{chip}</div></div>')

    why_heading = "Why it was blocked" if len(why_items) == 1 else f'Why it was blocked ({len(why_items)} matches)'
    why_html = f'<section><h2 class="section-title">{esc(why_heading)}</h2><div>{"".join(why_items)}</div></section>'

    dns_rows = []
    if details["rules"]:
        for item in details["services"]:
            dns_rows.append(f'<div class="row"><div class="label">Service</div><div class="value">{esc(item["value"])}</div></div>')
    for item in details["cnames"]:
        dns_rows.append(f'<div class="row"><div class="label">CNAME</div><div class="value mono">{esc(item["value"])}</div></div>')
    for item in details["rewrites"]:
        label = "IPv6 rewrite" if ":" in item["value"] else "IPv4 rewrite"
        dns_rows.append(f'<div class="row"><div class="label">{label}</div><div class="value mono">{esc(item["value"])}</div></div>')
    dns_html = f'<section><h2 class="section-title">DNS details</h2><div class="dns-grid">{"".join(dns_rows)}</div></section>' if dns_rows else ""

    technical = []
    current = device.get("current") or ""
    if current:
        technical.append(f'<div>Connection source: <span class="mono">{esc(current)}</span></div>')
    for reason in details["reasons"]:
        if reason["raw"]:
            qtypes = types_text(reason["types"])
            suffix = f" · {qtypes}" if qtypes else ""
            technical.append(f'<div>AdGuard result: <span class="mono">{esc(reason["raw"] + suffix)}</span></div>')
    technical_html = f'<details><summary>Technical details</summary><div class="technical">{"".join(technical)}</div></details>' if technical else ""
    note = "" if details["api_ok"] else '<p class="note">Detailed AdGuard information is temporarily unavailable.</p>'

    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark"><meta name="theme-color" media="(prefers-color-scheme:light)" content="#ffffff"><meta name="theme-color" media="(prefers-color-scheme:dark)" content="#171717"><title>Blocked — {esc(host)}</title><style>{CSS}</style></head><body><main><header><p class="eyebrow">DNS filtering</p><h1 class="title">Blocked</h1><p class="lead">Your network prevented this destination from loading.</p><div class="domain">{esc(host)}</div></header>{device_html}{why_html}{dns_html}{technical_html}{note}</main></body></html>'''.encode()


class Handler(BaseHTTPRequestHandler):
    def request_host(self):
        value = (self.headers.get("Host") or "").strip()
        if value.startswith("[") and "]" in value:
            return value[1:value.index("]")].lower().rstrip(".")
        return value.split(":", 1)[0].lower().rstrip(".")

    def reply(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()

    def do_GET(self):
        if self.path == "/healthz":
            body = b'{"ok":true}'
            self.reply(200, body, "application/json")
            self.wfile.write(body)
            return

        host = self.request_host()
        if not host or is_ip(host):
            body = render_status(host or "block page")
            self.reply(200, body, "text/html; charset=utf-8")
            self.wfile.write(body)
            return

        client_ip = normalize_ip(self.client_address[0])
        body = render_blocked(host, device_info(client_ip), block_details(host, client_ip))
        self.reply(200, body, "text/html; charset=utf-8")
        self.wfile.write(body)

    def do_HEAD(self):
        self.reply(200, b"", "text/html; charset=utf-8")

    def log_message(self, fmt, *args):
        print(f"{normalize_ip(self.client_address[0])} - {fmt % args}", flush=True)


class DualStackServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    allow_reuse_address = True

    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
        super().server_bind()


DualStackServer(("::", PORT), Handler).serve_forever()
