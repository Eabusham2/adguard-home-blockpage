#!/usr/bin/env python3
import base64
import html
import ipaddress
import json
import os
import re
import socket
import struct
import threading
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
AGH_QUERYLOG_FILE = os.getenv("AGH_QUERYLOG_FILE", "/opt/adguardhome/work/data/querylog.json")
AGH_CONFIG_FILE = os.getenv("AGH_CONFIG_FILE", "/opt/adguardhome/conf/AdGuardHome.yaml")
LOCAL_QUERYLOG_TAIL_BYTES = int(os.getenv("AGH_QUERYLOG_TAIL_BYTES", "1048576"))
APP_VERSION = "0.9.8-r1"

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
    "user_rules": [],
    "filter_state_bases": [],
    "filter_state_errors": [],
}


def auth_headers():
    headers = {"Accept": "application/json"}
    if AGH_USERNAME:
        token = base64.b64encode(f"{AGH_USERNAME}:{AGH_PASSWORD}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    return headers


def api_bases():
    # Prefer the explicitly configured AdGuard instance.  Localhost is only a
    # fallback; it must never silently override the configured server's state.
    bases = [AGH_URL.rstrip("/"), "http://127.0.0.1:3000"]
    out = []
    for base in bases:
        if base and base not in out:
            out.append(base)
    return out


def api_get_from(base, path, params=None, timeout=2.0):
    suffix = path
    if params:
        suffix += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(base.rstrip("/") + suffix, headers=auth_headers())
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode())


def api_get(path, params=None, timeout=2.0):
    suffix = path
    if params:
        suffix += "?" + urllib.parse.urlencode(params)
    last_error = None
    for base in api_bases():
        try:
            req = urllib.request.Request(base + suffix, headers=auth_headers())
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return json.loads(response.read().decode())
        except Exception as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise RuntimeError("No AdGuard API endpoint configured")


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


def api_post(path, payload, timeout=2.0):
    headers = auth_headers()
    headers["Content-Type"] = "application/json"
    last_error = None
    for base in api_bases():
        try:
            req = urllib.request.Request(
                base + path,
                data=json.dumps(payload).encode(),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return json.loads(response.read().decode())
        except Exception as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise RuntimeError("No AdGuard API endpoint configured")

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


def parse_yaml_scalar(value):
    value = str(value or "").strip()
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        try:
            return json.loads(value)
        except Exception:
            return value[1:-1]
    return value


def local_user_filter_rules():
    """Read top-level user_rules directly from AdGuardHome.yaml.

    Returns (rules, error).  rules is None when the config file isn't mounted or
    readable; an empty list means the file was read successfully and contains no
    custom rules.
    """
    try:
        with open(AGH_CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"

    rules = []
    in_rules = False
    base_indent = 0
    for line in lines:
        raw = line.rstrip("\n\r")
        stripped = raw.strip()
        if not in_rules:
            m = re.match(r"^(\s*)user_rules\s*:\s*$", raw)
            if not m:
                continue
            in_rules = True
            base_indent = len(m.group(1))
            continue
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent <= base_indent and not raw.lstrip().startswith("-"):
            break
        item = raw.lstrip()
        if not item.startswith("-"):
            continue
        value = item[1:].strip()
        if value:
            rule = parse_yaml_scalar(value)
            if rule and rule not in rules:
                rules.append(rule)
    return rules, ""


def refresh_filter_state(force=False):
    now = time.time()
    if not force and CACHE["filters_until"] > now:
        return CACHE["filters"]

    names = dict(SPECIAL_LISTS)
    merged_rules = []
    working_bases = []
    errors = []

    # Read every reachable AdGuard API endpoint instead of trusting whichever
    # one happens to answer first.  This avoids classifying a duplicate custom
    # rule as a subscribed-list rule because one endpoint returned incomplete
    # or stale filtering state.
    for base in api_bases():
        try:
            status = api_get_from(base, "/control/filtering/status", timeout=2.0)
        except Exception as exc:
            errors.append(f"{base}: {api_error_text(exc)}")
            continue
        if not isinstance(status, dict):
            errors.append(f"{base}: invalid filtering/status response")
            continue
        working_bases.append(base)
        for section in ("filters", "whitelist_filters"):
            for item in status.get(section, []) or []:
                filter_id = item.get("id")
                name = item.get("name")
                if filter_id is not None and name and str(filter_id) != "0":
                    names[str(filter_id)] = str(name)
        for rule in status.get("user_rules", []) or []:
            rule = str(rule).strip()
            if rule and rule not in merged_rules:
                merged_rules.append(rule)

    if not working_bases:
        CACHE["filter_state_errors"] = errors[:4]
        return CACHE["filters"] or dict(SPECIAL_LISTS)

    CACHE["filters"] = names
    CACHE["user_rules"] = merged_rules
    CACHE["filter_state_bases"] = working_bases
    CACHE["filter_state_errors"] = errors[:4]
    CACHE["filters_until"] = now + 30
    return names

def filter_names():
    return refresh_filter_state(False)


def user_filter_rules(force=False):
    local_rules, local_error = local_user_filter_rules()
    if local_rules is not None:
        CACHE["user_rules"] = local_rules
        CACHE["user_rules_source"] = "local config"
        CACHE["user_rules_error"] = ""
        return list(local_rules)

    CACHE["user_rules_source"] = "filtering API fallback"
    CACHE["user_rules_error"] = local_error
    refresh_filter_state(force)
    return list(CACHE.get("user_rules") or [])


def normalized_rule_text(value):
    return str(value or "").strip().replace("\r\n", "\n").replace("\r", "\n")

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
    # Best-effort only.  The on-disk format normally stores the client IP rather
    # than the resolved runtime name, so other client/neighbor/rDNS sources remain
    # primary.  Crucially, this never calls the Query Log HTTP API.
    try:
        lines = tail_json_lines(AGH_QUERYLOG_FILE, min(LOCAL_QUERYLOG_TAIL_BYTES, 524288))
    except Exception:
        return ""
    target = normalize_ip(client_ip)
    for raw in reversed(lines):
        try:
            entry = json.loads(raw)
        except Exception:
            continue
        logged = normalize_ip(str(entry.get("IP") or entry.get("client") or ""))
        if logged and logged != target:
            continue
        for key in ("ClientName", "client_name", "clientName"):
            name = str(entry.get(key) or "").strip()
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


def custom_rule_matches_host(rule, host):
    raw = str(rule or "").strip()
    host = str(host or "").strip().lower().rstrip(".")
    if not raw or not host or raw.startswith(("!", "#", "@@")):
        return False

    # Hosts-file style custom rules.
    parts = raw.split()
    if len(parts) >= 2 and is_ip(parts[0]):
        return any(str(x).lower().rstrip(".") == host for x in parts[1:])

    # Regex custom rules.
    if raw.startswith("/"):
        last = raw.rfind("/")
        if last > 0:
            try:
                return re.search(raw[1:last], host, re.I) is not None
            except re.error:
                return False

    body = raw.split("$", 1)[0].strip()
    if body.startswith("||"):
        body = body[2:]
        body = re.split(r"[\^/|]", body, maxsplit=1)[0]
        body = body.strip(".").lower()
        if not body:
            return False
        if "*" in body:
            pattern = "^" + re.escape(body).replace(r"\*", ".*") + "$"
            return re.match(pattern, host, re.I) is not None
        return host == body or host.endswith("." + body)

    body = body.strip("|").strip().lower().rstrip(".")
    if "*" in body:
        pattern = "^" + re.escape(body).replace(r"\*", ".*") + "$"
        return re.match(pattern, host, re.I) is not None
    return body == host


def custom_rule_types(rule):
    lower = str(rule or "").lower()
    m = re.search(r"(?:^|[,;$])dnstype=([^,$]+)", lower)
    if not m:
        return ["A", "AAAA"]
    value = m.group(1).upper()
    out = []
    if "A" in value.split("|"):
        out.append("A")
    if "AAAA" in value.split("|"):
        out.append("AAAA")
    return out or ["A", "AAAA"]


def tail_json_lines(path, max_bytes):
    """Read only the newest bounded chunk of a JSON-lines file."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        start = max(0, size - max(4096, int(max_bytes)))
        f.seek(start)
        data = f.read()
    if start > 0:
        nl = data.find(b"\n")
        data = b"" if nl < 0 else data[nl + 1:]
    return data.splitlines()


def local_log_entry(entry):
    """Convert AdGuard's on-disk querylog JSON shape to the API-like shape."""
    if not isinstance(entry, dict):
        return "", "", "", {}

    host = str(entry.get("QH") or "").lower().rstrip(".")
    qtype = str(entry.get("QT") or "").upper()
    client = normalize_ip(str(entry.get("IP") or ""))
    question = entry.get("question") or {}
    if not host:
        host = str(question.get("host") or question.get("name") or "").lower().rstrip(".")
    if not qtype:
        qtype = str(question.get("type") or "").upper()
    if not client:
        client = normalize_ip(str(entry.get("client") or ""))

    result = entry.get("Result") if isinstance(entry.get("Result"), dict) else {}
    reason = result.get("Reason", entry.get("reason", ""))
    service = str(result.get("ServiceName") or result.get("Service") or entry.get("service_name") or "").strip()

    raw_rules = result.get("Rules") or result.get("rules") or entry.get("rules") or []
    if isinstance(raw_rules, dict):
        raw_rules = [raw_rules]
    rules = []
    for rule in raw_rules:
        if isinstance(rule, str):
            text, fid = rule, None
        elif isinstance(rule, dict):
            text = str(rule.get("Text") or rule.get("text") or rule.get("Rule") or rule.get("rule") or "").strip()
            fid = rule.get("FilterListID", rule.get("FilterID", rule.get("filter_list_id", rule.get("filter_id"))))
        else:
            continue
        if text:
            rules.append({"text": text, "filter_list_id": fid})

    if not rules:
        text = str(result.get("Rule") or entry.get("rule") or "").strip()
        fid = result.get("FilterID", result.get("FilterId", entry.get("filter_id", entry.get("filterId"))))
        if text:
            rules.append({"text": text, "filter_list_id": fid})

    if isinstance(reason, str):
        reason_name = reason.strip()
    else:
        reason_name = ""
    if not reason_name:
        if service:
            reason_name = "FilteredBlockedService"
        elif rules or result.get("IsFiltered"):
            reason_name = "FilteredBlackList"

    converted = {
        "reason": reason_name,
        "rules": rules,
        "service_name": service,
    }
    return host, qtype, client, converted


def local_querylog_matches(host, client_ip):
    errors = []
    path = AGH_QUERYLOG_FILE
    if not path:
        return [], ["local query log path is empty"]
    try:
        lines = tail_json_lines(path, LOCAL_QUERYLOG_TAIL_BYTES)
    except Exception as exc:
        return [], [f"{type(exc).__name__}: {exc}"]

    target_host = str(host or "").lower().rstrip(".")
    target_client = normalize_ip(client_ip)
    exact = []
    # Newest first.  A partially-written final line is harmless and skipped.
    for raw in reversed(lines):
        if not raw.strip():
            continue
        try:
            entry = json.loads(raw)
        except Exception:
            continue
        qhost, qtype, logged_client, converted = local_log_entry(entry)
        if qhost != target_host:
            continue
        score = 1 if logged_client and logged_client == target_client else 0
        exact.append((score, qtype, converted))
        if len(exact) >= 12:
            break
    exact.sort(key=lambda x: x[0], reverse=True)
    return exact[:8], errors


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
    current_user_rules = user_filter_rules(force=True)
    user_rule_by_text = {normalized_rule_text(x): x for x in current_user_rules}
    reasons = {}
    rules = {}
    services = {}
    cnames = {}
    rewrites = {}
    api_ok = False
    api_errors = []
    detail_source = "check_host"

    def ingest(data, qtype):
        nonlocal api_ok
        if not isinstance(data, dict) or not data:
            return
        api_ok = True
        raw_reason = str(data.get("reason") or "").strip()
        if raw_reason:
            item = reasons.setdefault(raw_reason, {"raw": raw_reason, "friendly": FRIENDLY_REASONS.get(raw_reason, raw_reason), "types": []})
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
            # AdGuard may report a subscribed-list ID even when the exact same rule
            # also exists in Custom filtering rules.  The user-rules collection is
            # authoritative for the label in that case.
            exact_user_rule = user_rule_by_text.get(normalized_rule_text(text))
            if exact_user_rule is not None:
                text = exact_user_rule
                list_name = "Custom rule"
            else:
                list_name = names.get(str(filter_id), f"Filter #{filter_id}") if filter_id is not None else ""
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

    if not api_ok:
        data, errors = check_host_plain(host)
        for error in errors:
            entry = f"plain: {error}"
            if entry not in api_errors:
                api_errors.append(entry)
        ingest(data, "")

    # The DNS query necessarily happened before this HTTP block page loaded.
    # Inspect the on-disk Query Log directly as well as check_host.  This deliberately
    # avoids the Query Log HTTP API, which can be expensive on a busy or unhealthy AdGuard
    # instance.  A local record with filter_list_id=0 is authoritative custom-rule
    # evidence.
    logged, errors = local_querylog_matches(host, client_ip)
    for error in errors:
        entry = f"querylog: {error}"
        if entry not in api_errors:
            api_errors.append(entry)
    if logged:
        if not api_ok or not rules:
            detail_source = "local query log"
        for _, qtype, entry in logged:
            ingest(entry, qtype if qtype in ("A", "AAAA") else "")

    # AdGuard may report only one winning block-list rule even when the same host
    # also matches a user rule.  Explicitly surface matching user rules as Custom rule.
    custom_found = False
    for text in current_user_rules:
        if not custom_rule_matches_host(text, host):
            continue
        custom_found = True
        key = ("Custom rule", text)
        item = rules.setdefault(key, {"list": "Custom rule", "rule": text, "kind": rule_kind(text), "types": []})
        for qtype in custom_rule_types(text):
            merge_types(item["types"], qtype)
    # If either user_rules or Query Log produced a Custom rule for the same exact
    # rule text, Custom rule wins and the duplicate subscribed-list card is hidden.
    custom_texts = {
        normalized_rule_text(item["rule"])
        for item in rules.values()
        if item.get("list") == "Custom rule"
    }
    if custom_texts:
        for key, item in list(rules.items()):
            if item.get("list") != "Custom rule" and normalized_rule_text(item.get("rule")) in custom_texts:
                del rules[key]
    if custom_found and not any(r.get("raw") for r in reasons.values()):
        reasons["FilteredBlackList"] = {"raw": "FilteredBlackList", "friendly": "DNS blocklist", "types": ["A", "AAAA"]}

    if not reasons:
        reasons[""] = {"raw": "", "friendly": "Network filtering", "types": []}

    result = {
        "reasons": list(reasons.values()),
        "rules": sorted(rules.values(), key=lambda x: (0 if x.get("list") == "Custom rule" else 1, x.get("list", ""), x.get("rule", ""))),
        "services": list(services.values()),
        "cnames": list(cnames.values()),
        "rewrites": list(rewrites.values()),
        "api_ok": api_ok or bool(rules),
        "api_errors": api_errors[:4],
        "stale": False,
        "detail_source": detail_source,
        "custom_rule_count": len(current_user_rules),
        "custom_match": any(custom_rule_matches_host(x, host) for x in current_user_rules),
        "filter_state_bases": list(CACHE.get("filter_state_bases") or []),
        "filter_state_errors": list(CACHE.get("filter_state_errors") or []),
        "user_rules_source": CACHE.get("user_rules_source", ""),
        "user_rules_error": CACHE.get("user_rules_error", ""),
        "querylog_file": AGH_QUERYLOG_FILE,
        "querylog_local": os.path.isfile(AGH_QUERYLOG_FILE),
    }
    cache_key = host.casefold()
    if result["api_ok"]:
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
FAVICON_ICO = base64.b64decode("AAABAAQAEBAAAAAAIABvAQAARgAAACAgAAAAACAAzgEAALUBAAAwMAAAAAAgADQCAACDAwAAQEAAAAAAIAAaAQAAtwUAAIlQTkcNChoKAAAADUlIRFIAAAAQAAAAEAgGAAAAH/P/YQAAATZJREFUeJylkz1LA0EQhp/ZvUsMGM1HpYEgQayihf4XhfwRBT9A/DmiCPaCv0BTiKCtNhaJRkJIvL21uPO4zXnXZLrdnXd455kdud1qWxYItYgYwMvciBQrrGvYLSCCDYJMkpPiuZLUSQinU0qNJqIU8H+R2WCAaJ049QBEa36+Pmnv9+ienkda7eKxxiBa835zRf/kCL9axYZh7ECE0Bgq6y1KjWZ+/8ByZzNqMXYgyRitRXyf2vYOonRWGYu+X1+YDQcRC2tTDJTCjMcMHx8iBjkgg8kEXS4n7y6Dgx7dswsEQGlITfSPwdv1Jf3jwxwGay1KtXoxg41OAQPtUd/di8aUSkozGD0/RaP0/TkGIlgT8HF/l/cFANCVpUScMEgX8VdWC1uwYegAzuyCNaawwHwsvI2/tuR1gBXKDxQAAAAASUVORK5CYIKJUE5HDQoaCgAAAA1JSERSAAAAIAAAACAIBgAAAHN6evQAAAGVSURBVHic7ZbLShxRFEXXOXXroU0j2rSCAydCpvmGEJyInyGSQT4jkBDQn1Fw6gMhJHEa8gcBxfaBPamuusdBNdJa1W1KhXZQe3xgr/OoXVd2360YU5RO07wBaADeBIB7skLkZQ42+SufCCCq+MHgRf4SBEUTY0DGA4iQ9fvEnQ6oggF1hjGsH9zcYHmORlElRDWAKnm/z/L6Bu+/biMuQERqEZj3iCoXP3/w+/MWlmXDRh5CSCmKRbA8x7VarJ2c4lqt/zYdp7873/nz7Qtxt1uAjKh6At6jUUSQJMUNmD3rGC3L0DgmnJvD8ryypgxghjhH2utxdnTA0oePtY3vFYaY95wfH+JmZzHvSyXlFQCI4NOUIElY3fyEhmF9czNQpXf6i3/7e0QLncopVAMMIfCe9PqquGjq/rUFMII4wbXbNVYw0oE4RzS/UNP4EYZq5eifBhAhu71tcqDJgSYHSK8u60cADGPA0GSGsN0udl+xxok5gCpxd/EZ7iPyvuh8zA1NfhGZla72tTX1N2ED0ABMHeAOsw/nlD7c5CcAAAAASUVORK5CYIKJUE5HDQoaCgAAAA1JSERSAAAAMAAAADAIBgAAAFcC+YcAAAH7SURBVHic7Zi7jtQwFIa/Y8fZkdiZgHZoKCiplu1Ws4hXQEhUFHS0VDwLDTTQAEKi5BEQSDQU0DGioGUlBuamJXFsinAT7Ew8kFEY4a+IFOkkPr99fPwn8uTcWc8Go9pO4G+JAtomCmibKKBtooC2iQLaZuMFJKsEi1I4a4F1+D8B7xGlEK3xzgU9FSbAe8QY7HSKyTJEZA0aPIjgioLy6Ajd6eCtBZGlTwUJkCTh8+F7+gcXufDwMSpJal+8MqUDESZvhzy7egU7nZCc2MaX5fLc6r4HRGvsbMbO/oDBvfuYbq/RvI/j4+tXvLh+jXz0AWXSpeVUu4lFKYrxJ85cuozp9nB53miyv+KLnJPn98h297CzWe1KB3Uh0Zp8NKpmounS+W0whbMF5XyOaF0bHrQHfFlielnVhfIcrzX4hnexVBfvHCpN0Z0OBHSiWgHOWrb6pxnevkV/cEC2u9dAtouRNOXdowccPn+K6WW17bR2E1dRinI+JT21w/6duyhjmsr3O945RCkmwze8vHmDZLtblVDNSocJ4MchVozHrOcg+zqO1pheVt0ElGnwSfxthrb6/T9OLmwgX9v7f2YlKwFUp+M/RPRCzRG90IKA6IVWI3qh44heaAWiF1oYGL1Q6ED/mRfa+B9bUUDbRAFtEwW0TRTQNlFA23wBEYou2QTji6oAAAAASUVORK5CYIKJUE5HDQoaCgAAAA1JSERSAAAAQAAAAEAIBgAAAKppcd4AAADhSURBVHic7ZnBDYNADMBC1TnoryzDtu0yPDtJ+2KBhMqRYv8PfNYJRFhez/Ubg7nRAjQGoAVoDEAL0BiAFqAxAC1AYwBagMYAtACNAWgBGgPQAjQGoAVo7tUL7MfnCo8S7+2RXls6AR02H1HzSAfosvmTrM/4Z4ABaAEaA2QXVl49/yDrUzoBXSJUPBZ/jg7HALQAjQFoAZrxAZwHVG7cYfMRzgMiwnlAGgPQAjQGyC7s8il84jwgifMAWoDGALQAjQFoARoD0AI0BqAFaAxAC9AYgBagMQAtQGMAWoBmfIAfdawkZI4y47UAAAAASUVORK5CYII=")
FAVICON_PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAA4UlEQVR4nO2ZwQ2DQAzAQtU56K8sw7btMjw7SftigYTKkWL/D3zWCURYXs/1G4O50QI0BqAFaAxAC9AYgBagMQAtQGMAWoDGALQAjQFoARoD0AI0BqAFaO7VC+zH5wqPEu/tkV5bOgEdNh9R80gH6LL5k6zP+GeAAWgBGgNkF1ZePf8g61M6AV0iVDwWf44OxwC0AI0BaAGa8QGcB1Ru3GHzEc4DIsJ5QBoD0AI0Bsgu7PIpfOI8IInzAFqAxgC0AI0BaAEaA9ACNAagBWgMQAvQGIAWoDEALUBjAFqAZnyAH3WsJGSOMuO1AAAAAElFTkSuQmCC")
FAVICON_DATA_URI = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PHJlY3Qgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiByeD0iMTQiIGZpbGw9IiNiMzI2MWUiLz48cGF0aCBkPSJNMTggMjFoMjh2N0gxOHptMCAxNWgyOHY3SDE4eiIgZmlsbD0iI2ZmZiIvPjwvc3ZnPg=="

def render_status(host):
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark"><link rel="icon" type="image/x-icon" sizes="32x32" href="/favicon.ico?v=098"><link rel="shortcut icon" type="image/x-icon" href="/favicon.ico?v=098"><link rel="icon" type="image/png" sizes="64x64" href="/favicon.png?v=098"><link rel="icon" type="image/svg+xml" href="/favicon.svg?v=098"><title>Block page</title><style>{CSS}</style></head><body><main class="status"><header><h1 class="title">Block page</h1><p class="lead">The service is running and ready for AdGuard Home.</p><div class="domain">{esc(host)}</div></header></main></body></html>'''.encode()


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
    if details.get("detail_source") == "local query log":
        technical.append('<div>Rule source: <span class="mono">local query log</span></div>')
    technical.append(f'<div>Query log: <span class="mono">{"local file" if details.get("querylog_local") else "local file unavailable"}</span></div>')
    if details.get("user_rules_source"):
        technical.append(f'<div>Custom rules source: <span class="mono">{esc(details["user_rules_source"])}</span></div>')
    if details.get("user_rules_error"):
        technical.append(f'<div>Local config error: <span class="mono">{esc(details["user_rules_error"])}</span></div>')
    technical.append(f'<div>Custom rules loaded: <span class="mono">{esc(details.get("custom_rule_count", 0))}</span></div>')
    technical.append(f'<div>Custom rule match: <span class="mono">{"yes" if details.get("custom_match") else "no"}</span></div>')
    if details.get("filter_state_bases"):
        technical.append(f'<div>Filter state API: <span class="mono">{esc(", ".join(details["filter_state_bases"]))}</span></div>')
    for error in details.get("filter_state_errors", []):
        technical.append(f'<div>Filter-state error: <span class="mono">{esc(error)}</span></div>')
    if details.get("stale"):
        technical.append('<div>AdGuard API: <span class="mono">temporarily unavailable; showing last known match</span></div>')
    for error in details.get("api_errors", []):
        technical.append(f'<div>API error: <span class="mono">{esc(error)}</span></div>')
    technical_html = f'<details><summary>Technical details</summary><div class="technical">{"".join(technical)}</div></details>'
    note = "" if details["api_ok"] or details.get("stale") else '<p class="note">AdGuard is answering DNS, but its filtering API did not return details for this request.</p>'

    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark"><link rel="icon" type="image/x-icon" sizes="32x32" href="/favicon.ico?v=098"><link rel="shortcut icon" type="image/x-icon" href="/favicon.ico?v=098"><link rel="icon" type="image/png" sizes="64x64" href="/favicon.png?v=098"><link rel="icon" type="image/svg+xml" href="/favicon.svg?v=098"><title>Blocked — {esc(host)}</title><style>{CSS}</style></head><body><main><header><p class="eyebrow">DNS filtering</p><h1 class="title">Blocked</h1><p class="lead">Your network prevented this destination from loading.</p><div class="domain">{esc(host)}</div></header>{device_html}{blocked_html}{dns_html}{technical_html}{note}</main></body></html>'''.encode()


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
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; img-src 'self' data:; connect-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
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
        if path in ("/favicon.png", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"):
            self.reply(200, FAVICON_PNG, "image/png")
            try:
                self.wfile.write(FAVICON_PNG)
            except (BrokenPipeError, ConnectionResetError):
                pass
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
        if path in ("/favicon.png", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"):
            self.reply(200, b"", "image/png")
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


def reject_https_probes(port=443):
    """Immediately reset HTTPS probes so HTTPS-upgrade browsers can fall back to HTTP.

    This is intentionally not a TLS server: no certificate, decryption, or interception.
    """
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
        sock.bind(("::", port))
        sock.listen(64)
        while True:
            conn, _ = sock.accept()
            try:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except OSError:
                pass
            conn.close()
    except Exception as exc:
        print(f"HTTPS reject listener unavailable on port {port}: {type(exc).__name__}: {exc}", flush=True)
    finally:
        try:
            sock.close()
        except Exception:
            pass


threading.Thread(target=reject_https_probes, name="https-reject", daemon=True).start()
DualStackServer(("::", PORT), Handler).serve_forever()
