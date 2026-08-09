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
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AGH_URL = os.getenv("AGH_URL", "").rstrip("/")
AGH_USERNAME = os.getenv("AGH_USERNAME", "")
AGH_PASSWORD = os.getenv("AGH_PASSWORD", "")
PORT = int(os.getenv("PORT", "80"))
APP_VERSION = "0.9.2"

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
    "0": "Custom rule",
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
    "block_details": {},
}


def auth_headers():
    headers = {"Accept": "application/json"}
    if AGH_USERNAME:
        token = base64.b64encode(f"{AGH_USERNAME}:{AGH_PASSWORD}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    return headers


def api_get(path, params=None, timeout=3):
    url = AGH_URL + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=auth_headers())
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode())


def api_error_text(exc):
    if isinstance(exc, urllib.error.HTTPError):
        detail = ""
        try:
            detail = exc.read(240).decode("utf-8", "replace").strip()
        except Exception:
            pass
        text = f"HTTP {exc.code} {exc.reason}"
        return f"{text}: {detail}" if detail else text
    if isinstance(exc, urllib.error.URLError):
        return f"Connection error: {exc.reason}"
    return f"{type(exc).__name__}: {exc}"


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
                if filter_id is not None and name and str(filter_id) != "0":
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

    add_address(client_ip)
    client = find_client_by_ip(client_ip)
    if client:
        info["name"] = str(client.get("name") or "").strip()
        for address in address_set(client):
            add_address(address)
        for mac in mac_ids(client):
            add_mac(mac)

    neighbors = neighbor_entries()
    current_macs = [mac for addr, mac in neighbors if addr == client_ip]
    for mac in current_macs:
        add_mac(mac)
        for addr, neighbor_mac in neighbors:
            if neighbor_mac == mac:
                add_address(addr)

    for address in list(info["addresses"]):
        candidate = find_client_by_ip(address)
        if candidate:
            if not info["name"]:
                info["name"] = str(candidate.get("name") or "").strip()
            for extra in address_set(candidate):
                add_address(extra)
            for mac in mac_ids(candidate):
                add_mac(mac)

    if not info["name"]:
        for address in list(info["addresses"]):
            name = name_from_clients_search(address) or name_from_querylog(address)
            if name:
                info["name"] = name
                break

    if info["name"]:
        candidate = find_client_by_name(info["name"])
        if candidate:
            for address in address_set(candidate):
                add_address(address)
            for mac in mac_ids(candidate):
                add_mac(mac)

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
    attempts = []
    variants = [
        {"name": host, "client": client_ip, "qtype": qtype},
        {"name": host, "qtype": qtype},
    ]
    for params in variants:
        try:
            data = api_get("/control/filtering/check_host", params, timeout=2.5)
            if isinstance(data, dict):
                return data, attempts
            attempts.append("Invalid JSON response")
        except Exception as exc:
            attempts.append(api_error_text(exc))
    return {}, attempts


def check_host_plain(host):
    try:
        data = api_get("/control/filtering/check_host", {"name": host}, timeout=2.5)
        return (data if isinstance(data, dict) else {}), []
    except Exception as exc:
        return {}, [api_error_text(exc)]


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


def display_filter_name(filter_id, list_name, rule_text):
    name = str(list_name or "").strip()
    lowered = name.casefold()
    if str(filter_id) == "0" or lowered in {
        "custom filtering rules",
        "custom rules",
        "user rules",
        "user filtering rules",
        "custom dns filter",
        "custom rule",
    }:
        return "Custom rule"
    if filter_id is None and str(rule_text or "").strip():
        return "Custom rule"
    return name or "Filtering rule"


def block_details(host, client_ip):
    names = filter_names()
    reasons = {}
    rules = {}
    services = {}
    cnames = {}
    rewrites = {}
    api_ok = False
    api_errors = []

    def ingest(data, qtype):
        nonlocal api_ok
        if not isinstance(data, dict) or not data:
            return
        api_ok = True

        raw_reason = str(data.get("reason") or "").strip()
        if raw_reason:
            item = reasons.setdefault(
                raw_reason,
                {"raw": raw_reason, "friendly": FRIENDLY_REASONS.get(raw_reason, raw_reason), "types": []},
            )
            if qtype:
                merge_types(item["types"], qtype)

        service = str(data.get("service_name") or "").strip()
        if service:
            item = services.setdefault(service, {"value": service, "types": []})
            if qtype:
                merge_types(item["types"], qtype)

        cname = str(data.get("cname") or "").strip()
        if cname:
            item = cnames.setdefault(cname, {"value": cname, "types": []})
            if qtype:
                merge_types(item["types"], qtype)

        for address in data.get("ip_addrs", []) or []:
            address = normalize_ip(str(address))
            if address:
                item = rewrites.setdefault(address, {"value": address, "types": []})
                if qtype:
                    merge_types(item["types"], qtype)

        matched = data.get("rules") or []
        if isinstance(matched, dict):
            matched = [matched]
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
            list_name = display_filter_name(filter_id, list_name, text)

            key = (list_name, text)
            item = rules.setdefault(key, {"list": list_name, "rule": text, "kind": rule_kind(text), "types": []})
            if qtype:
                merge_types(item["types"], qtype)

    for qtype in ("A", "AAAA"):
        data, errors = check_host(host, client_ip, qtype)
        for error in errors:
            entry = f"{qtype}: {error}"
            if entry not in api_errors:
                api_errors.append(entry)
        ingest(data, qtype)

    # Older/newer AGH builds or a temporarily unhappy client-specific lookup can
    # still answer the simple documented host check.  Use it only if both typed
    # lookups failed so we do not duplicate normal results.
    if not api_ok:
        data, errors = check_host_plain(host)
        for error in errors:
            entry = f"plain: {error}"
            if entry not in api_errors:
                api_errors.append(entry)
        ingest(data, "")

    if not reasons:
        reasons[""] = {"raw": "", "friendly": "Network filtering", "types": []}

    result = {
        "reasons": list(reasons.values()),
        "rules": list(rules.values()),
        "services": list(services.values()),
        "cnames": list(cnames.values()),
        "rewrites": list(rewrites.values()),
        "api_ok": api_ok,
        "api_errors": api_errors[:4],
        "stale": False,
    }

    cache_key = host.casefold()
    if api_ok:
        CACHE["block_details"][cache_key] = {"time": time.time(), "data": result}
        return result

    cached = CACHE["block_details"].get(cache_key)
    if cached and time.time() - cached.get("time", 0) <= 900:
        saved = dict(cached.get("data") or {})
        if saved:
            saved["api_ok"] = False
            saved["stale"] = True
            saved["api_errors"] = api_errors[:4]
            return saved

    return result


def esc(value):
    return html.escape(str(value), quote=True)


CSS = r'''
:root{color-scheme:light dark;--bg:#fff;--text:#1b1b1b;--muted:#747474;--line:#e1e1e1;--soft:#f7f7f7;--code:#f4f4f4}
@media(prefers-color-scheme:dark){:root{--bg:#171717;--text:#f1f1f1;--muted:#aaa;--line:#383838;--soft:#1f1f1f;--code:#222}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}body{margin:0;background:var(--bg);color:var(--text);font:15.5px/1.42 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{width:min(710px,100%);margin:0 auto;padding:max(32px,env(safe-area-inset-top)) max(18px,env(safe-area-inset-right)) max(34px,env(safe-area-inset-bottom)) max(18px,env(safe-area-inset-left))}
header{padding-bottom:19px;border-bottom:1px solid var(--line)}.eyebrow{margin:0 0 4px;color:var(--muted);font-size:12.5px;font-weight:650}.title{margin:0;font-size:31px;line-height:1.08;letter-spacing:-.02em;font-weight:680}.lead{margin:6px 0 0;color:var(--muted)}.domain{margin-top:13px;padding:9px 11px;background:var(--soft);border:1px solid var(--line);border-radius:8px;font:600 16px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
section{margin-top:21px}.section-title{margin:0 0 7px;font-size:15px;font-weight:680}.panel{border:1px solid var(--line);border-radius:9px;overflow:hidden}.row{display:grid;grid-template-columns:102px minmax(0,1fr);gap:13px;padding:9px 12px;border-bottom:1px solid var(--line)}.row:last-child{border-bottom:0}.label{color:var(--muted)}.value{min-width:0;overflow-wrap:anywhere}.name{font-weight:650}.mono{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.rule{padding:11px 0;border-top:1px solid var(--line)}.rule:first-child{border-top:0}.rulehead{display:flex;justify-content:space-between;gap:8px 12px;align-items:center}.filter{font-weight:650;line-height:1.25}.meta{display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end}.pill{padding:1px 6px;border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:11px;line-height:1.6;white-space:nowrap}.ruletext{margin-top:6px;padding:8px 10px;background:var(--code);border-radius:6px;font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.fallback{padding:9px 11px;border:1px solid var(--line);border-radius:8px}details{margin-top:19px;border-top:1px solid var(--line);padding-top:9px}summary{color:var(--muted);cursor:pointer;font-size:13px}.technical{margin-top:6px;color:var(--muted);font-size:11.75px;line-height:1.32;display:grid;gap:2px}.technical div{margin:0;overflow-wrap:anywhere}.technical .mono{font-size:11.25px}.note{margin-top:12px;color:var(--muted);font-size:11.75px}.status{min-height:68vh;display:grid;align-content:center}.status header{border-bottom:0}
@media(max-width:520px){main{padding-left:14px;padding-right:14px;padding-top:max(24px,env(safe-area-inset-top))}.title{font-size:28.5px}.row{grid-template-columns:86px minmax(0,1fr);gap:9px;padding:8px 9px}.domain{font-size:15.25px}.mono,.ruletext{font-size:12.2px}.section-title{font-size:14.5px}}
@media(max-width:340px){.row{grid-template-columns:1fr;gap:2px}.rulehead{display:block}.meta{justify-content:flex-start;margin-top:4px}}
'''


def types_text(types):
    return " + ".join(types)


def display_device_name(name):
    name = str(name or "").strip().rstrip(".")
    lower = name.casefold()
    for suffix in (".home.arpa", ".local"):
        if lower.endswith(suffix):
            short = name[:-len(suffix)].rstrip(".")
            if short:
                return short
    return name


FAVICON_SVG = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#b3261e"/><path d="M18 21h28v7H18zm0 15h28v7H18z" fill="#fff"/></svg>'
FAVICON_ICO = base64.b64decode("AAABAAEAAQEAAAEAIABEAAAAFgAAAIlQTkcNChoKAAAADUlIRFIAAAABAAAAAQgEAAAAtRwMAgAAAAtJREFUeNpj/P8fAALrAfWPWeEtAAAAAElFTkSuQmCC")

def render_status(host):
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark"><link rel="icon" href="/favicon.svg" type="image/svg+xml"><title>Block page</title><style>{CSS}</style></head><body><main class="status"><header><h1 class="title">Block page</h1><p class="lead">The service is running and ready for AdGuard Home.</p><div class="domain">{esc(host)}</div></header></main></body></html>'''.encode()


def render_blocked(host, device, details):
    full_name = str(device.get("name") or "").strip().rstrip(".")
    short_name = display_device_name(full_name)
    ipv4 = [a for a in device.get("addresses", []) if ":" not in a]
    ipv6 = [a for a in device.get("addresses", []) if ":" in a]

    device_rows = []
    if short_name:
        device_rows.append(f'<div class="row"><div class="label">Name</div><div class="value name">{esc(short_name)}</div></div>')
    if ipv4:
        device_rows.append(f'<div class="row"><div class="label">IPv4</div><div class="value mono">{esc(", ".join(ipv4))}</div></div>')
    if ipv6:
        device_rows.append(f'<div class="row"><div class="label">IPv6</div><div class="value mono">{esc(", ".join(ipv6))}</div></div>')
    if device.get("macs"):
        device_rows.append(f'<div class="row"><div class="label">MAC</div><div class="value mono">{esc(", ".join(device["macs"]))}</div></div>')
    device_html = f'<section><h2 class="section-title">Device details</h2><div class="panel">{"".join(device_rows)}</div></section>' if device_rows else ""

    if details["rules"]:
        items = []
        for item in details["rules"]:
            source = esc(item["list"] or "Filtering rule")
            kind = esc(item.get("kind", "Rule"))
            qtypes = esc(types_text(item["types"]))
            badges = f'<span class="pill">{kind}</span>' + (f'<span class="pill">{qtypes}</span>' if qtypes else "")
            text = esc(item["rule"] or "Rule text unavailable")
            items.append(f'<div class="rule"><div class="rulehead"><div class="filter">{source}</div><div class="meta">{badges}</div></div><div class="ruletext">{text}</div></div>')
        blocked_html = f'<section><h2 class="section-title">Why it was blocked</h2>{"".join(items)}</section>'
    else:
        reason = details["reasons"][0]["friendly"] if details["reasons"] else "Network filtering"
        blocked_html = f'<section><h2 class="section-title">Why it was blocked</h2><div class="fallback">{esc(reason)}</div></section>'

    dns_rows = []
    for item in details["services"]:
        suffix = types_text(item["types"])
        text = item["value"] + (f" · {suffix}" if suffix else "")
        dns_rows.append(f'<div class="row"><div class="label">Service</div><div class="value">{esc(text)}</div></div>')
    for item in details["cnames"]:
        suffix = types_text(item["types"])
        text = item["value"] + (f" · {suffix}" if suffix else "")
        dns_rows.append(f'<div class="row"><div class="label">CNAME</div><div class="value mono">{esc(text)}</div></div>')
    for item in details["rewrites"]:
        suffix = types_text(item["types"])
        text = item["value"] + (f" · {suffix}" if suffix else "")
        dns_rows.append(f'<div class="row"><div class="label">Rewrite</div><div class="value mono">{esc(text)}</div></div>')
    dns_html = f'<section><h2 class="section-title">DNS details</h2><div class="panel">{"".join(dns_rows)}</div></section>' if dns_rows else ""

    technical = [f'<div>Version: <span class="mono">{esc(APP_VERSION)}</span></div>']
    current = device.get("current") or ""
    if full_name and short_name != full_name:
        technical.append(f'<div>Hostname: <span class="mono">{esc(full_name)}</span></div>')
    if current:
        technical.append(f'<div>Connection source: <span class="mono">{esc(current)}</span></div>')
    for reason in details["reasons"]:
        if reason["raw"]:
            qtypes = types_text(reason["types"])
            suffix = f" · {qtypes}" if qtypes else ""
            technical.append(f'<div>AdGuard reason: <span class="mono">{esc(reason["raw"] + suffix)}</span></div>')
    if details.get("stale"):
        technical.append('<div>AdGuard API: <span class="mono">temporarily unavailable; showing last known match</span></div>')
    for error in details.get("api_errors", []):
        technical.append(f'<div>API error: <span class="mono">{esc(error)}</span></div>')
    technical_html = f'<details><summary>Technical details</summary><div class="technical">{"".join(technical)}</div></details>'
    note = "" if details["api_ok"] or details.get("stale") else '<p class="note">AdGuard is answering DNS, but its filtering API did not return details for this request.</p>'

    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark"><link rel="icon" href="/favicon.svg" type="image/svg+xml"><title>Blocked — {esc(host)}</title><style>{CSS}</style></head><body><main><header><p class="eyebrow">DNS filtering</p><h1 class="title">Blocked</h1><p class="lead">Your network prevented this destination from loading.</p><div class="domain">{esc(host)}</div></header>{device_html}{blocked_html}{dns_html}{technical_html}{note}</main></body></html>'''.encode()


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
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; img-src 'self'; connect-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def no_content(self):
        self.send_response(204)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/healthz":
            body = b'{"ok":true}'
            self.reply(200, body, "application/json")
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if path == "/favicon.svg":
            self.reply(200, FAVICON_SVG, "image/svg+xml")
            try:
                self.wfile.write(FAVICON_SVG)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if path == "/favicon.ico":
            self.reply(200, FAVICON_ICO, "image/x-icon")
            try:
                self.wfile.write(FAVICON_ICO)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if path in ("/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"):
            self.no_content()
            return

        host = self.request_host()
        client_ip = normalize_ip(self.client_address[0])
        if host and not is_ip(host):
            body = render_blocked(host, device_info(client_ip), block_details(host, client_ip))
        else:
            body = render_status(host or "block page")
        self.reply(200, body, "text/html; charset=utf-8")
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_HEAD(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/favicon.svg":
            self.reply(200, b"", "image/svg+xml")
            return
        if path == "/favicon.ico":
            self.reply(200, b"", "image/x-icon")
            return
        if path in ("/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"):
            self.no_content()
            return
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
