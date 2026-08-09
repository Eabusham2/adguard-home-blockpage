#!/usr/bin/env python3
import base64
import html
import ipaddress
import json
import os
import socket
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


def find_client_by_ip(client_ip):
    client_ip = normalize_ip(client_ip)
    for client in client_catalog():
        values = {normalize_ip(x) for x in client.get("ip_addrs", [])}
        values.update(normalize_ip(x) for x in client.get("ids", []))
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
    info = {"name": "", "current": client_ip, "addresses": [client_ip] if client_ip else []}

    client = find_client_by_ip(client_ip)
    if client:
        info["name"] = str(client.get("name") or "").strip()
        for address in address_set(client):
            if address not in info["addresses"]:
                info["addresses"].append(address)
        return info

    name = name_from_clients_search(client_ip)
    if not name:
        name = name_from_querylog(client_ip)

    if name:
        info["name"] = name
        client = find_client_by_name(name)
        if client:
            for address in address_set(client):
                if address not in info["addresses"]:
                    info["addresses"].append(address)
        return info

    try:
        host = socket.gethostbyaddr(client_ip)[0].rstrip(".")
        if host and host != client_ip:
            info["name"] = host
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
            item = rules.setdefault(key, {"list": list_name, "rule": text, "types": []})
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
:root{color-scheme:light dark;--bg:#fff;--text:#171717;--muted:#666;--line:#dedede;--soft:#f5f5f5;--accent:#b42318}
@media(prefers-color-scheme:dark){:root{--bg:#151515;--text:#f1f1f1;--muted:#aaa;--line:#3a3a3a;--soft:#202020;--accent:#ff8b82}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{width:min(640px,100%);margin:0 auto;padding:max(36px,env(safe-area-inset-top)) max(18px,env(safe-area-inset-right)) max(36px,env(safe-area-inset-bottom)) max(18px,env(safe-area-inset-left))}
h1{margin:0;font-size:30px;line-height:1.15;letter-spacing:-.02em}.lead{margin:8px 0 22px;color:var(--muted)}.domain{margin:0 0 24px;padding:12px 14px;background:var(--soft);border:1px solid var(--line);border-radius:8px;font-weight:650;overflow-wrap:anywhere}
.info{border-top:1px solid var(--line)}.row{display:grid;grid-template-columns:120px minmax(0,1fr);gap:16px;padding:12px 0;border-bottom:1px solid var(--line)}.label{color:var(--muted)}.value{min-width:0;overflow-wrap:anywhere}.value strong{font-weight:650}.address{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
h2{margin:26px 0 8px;font-size:16px}.rule{padding:11px 0;border-top:1px solid var(--line)}.rule:first-of-type{border-top:0}.filter{font-weight:650}.rtype{margin-left:7px;color:var(--muted);font-size:12px;font-weight:400}.ruletext{margin-top:3px;color:var(--muted);font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
details{margin-top:24px;border-top:1px solid var(--line);padding-top:14px}summary{cursor:pointer;color:var(--muted);user-select:none}.technical{margin-top:10px;color:var(--muted);font-size:13px}.technical div{margin:4px 0;overflow-wrap:anywhere}.note{margin-top:20px;color:var(--muted);font-size:13px}
@media(max-width:500px){main{padding-left:14px;padding-right:14px}.row{grid-template-columns:1fr;gap:3px}h1{font-size:27px}}
'''


def types_text(types):
    return " + ".join(types)


def render_status(host):
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark"><title>Block page</title><style>{CSS}</style></head><body><main><h1>Block page</h1><p class="lead">The service is running.</p><div class="domain">{esc(host)}</div></main></body></html>'''.encode()


def render_blocked(host, device, details):
    primary_reason = details["reasons"][0]["friendly"]

    rows = [
        f'<div class="row"><div class="label">Reason</div><div class="value"><strong>{esc(primary_reason)}</strong></div></div>'
    ]

    if device.get("name"):
        rows.append(
            f'<div class="row"><div class="label">Device</div><div class="value"><strong>{esc(device["name"])}</strong></div></div>'
        )

    current = device.get("current") or ""
    if current:
        kind = "IPv6 address" if ":" in current else "IPv4 address"
        rows.append(
            f'<div class="row"><div class="label">{kind}</div><div class="value address">{esc(current)}</div></div>'
        )

    extras_v4 = [a for a in device.get("addresses", []) if a != current and ":" not in a]
    extras_v6 = [a for a in device.get("addresses", []) if a != current and ":" in a]
    if extras_v4:
        rows.append(
            f'<div class="row"><div class="label">Local IPv4</div><div class="value address">{esc(", ".join(extras_v4))}</div></div>'
        )
    if extras_v6:
        rows.append(
            f'<div class="row"><div class="label">Other IPv6</div><div class="value address">{esc(", ".join(extras_v6))}</div></div>'
        )

    for item in details["services"]:
        rows.append(
            f'<div class="row"><div class="label">Service</div><div class="value">{esc(item["value"])}</div></div>'
        )
    for item in details["cnames"]:
        rows.append(
            f'<div class="row"><div class="label">CNAME</div><div class="value address">{esc(item["value"])}</div></div>'
        )
    for item in details["rewrites"]:
        rows.append(
            f'<div class="row"><div class="label">Rewrite address</div><div class="value address">{esc(item["value"])}</div></div>'
        )

    rules_html = ""
    if details["rules"]:
        label = "Matched rule" if len(details["rules"]) == 1 else f'Matched rules ({len(details["rules"])})'
        items = []
        for item in details["rules"]:
            source = esc(item["list"] or "Filtering rule")
            qtypes = types_text(item["types"])
            type_badge = f'<span class="rtype">{esc(qtypes)}</span>' if qtypes else ""
            text = esc(item["rule"] or "Rule text unavailable")
            items.append(
                f'<div class="rule"><div class="filter">{source}{type_badge}</div><div class="ruletext">{text}</div></div>'
            )
        rules_html = f'<section><h2>{esc(label)}</h2>{"".join(items)}</section>'

    technical = []
    for reason in details["reasons"]:
        if reason["raw"]:
            qtypes = types_text(reason["types"])
            suffix = f" ({qtypes})" if qtypes else ""
            technical.append(f'<div>AdGuard reason: <span class="address">{esc(reason["raw"] + suffix)}</span></div>')
    if technical:
        technical_html = f'<details><summary>Technical details</summary><div class="technical">{"".join(technical)}</div></details>'
    else:
        technical_html = ""

    note = "" if details["api_ok"] else '<p class="note">Detailed AdGuard information is temporarily unavailable.</p>'

    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark"><meta name="theme-color" media="(prefers-color-scheme:light)" content="#ffffff"><meta name="theme-color" media="(prefers-color-scheme:dark)" content="#151515"><title>Blocked — {esc(host)}</title><style>{CSS}</style></head><body><main><h1>Blocked</h1><p class="lead">This address is blocked by your network.</p><div class="domain">{esc(host)}</div><section class="info">{"".join(rows)}</section>{rules_html}{technical_html}{note}</main></body></html>'''.encode()


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
