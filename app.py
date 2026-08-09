#!/usr/bin/env python3
import base64, html, ipaddress, json, os, socket, time, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AGH_URL = os.getenv("AGH_URL", "").rstrip("/")
AGH_USERNAME = os.getenv("AGH_USERNAME", "")
AGH_PASSWORD = os.getenv("AGH_PASSWORD", "")
PORT = int(os.getenv("PORT", "80"))

REASONS = {
    "NotFilteredNotFound": "No filtering rule matched",
    "NotFilteredWhiteList": "Allowed by an exception rule",
    "NotFilteredError": "Filtering check error",
    "FilteredBlackList": "Blocked by a DNS blocklist",
    "FilteredSafeBrowsing": "Blocked by Safe Browsing",
    "FilteredParental": "Blocked by parental controls",
    "FilteredInvalid": "Blocked because the request is invalid",
    "FilteredSafeSearch": "Safe Search was enforced",
    "FilteredBlockedService": "Blocked service",
    "Rewrite": "DNS rewrite",
    "RewriteEtcHosts": "Hosts-file rewrite",
    "RewriteRule": "DNS rewrite rule",
}
SPECIAL_LISTS = {
    "0": "Custom filtering rules",
    "-1": "System hosts file",
    "-2": "Blocked services",
    "-3": "Parental controls",
    "-4": "Safe Browsing",
    "-5": "Safe Search",
}
CACHE = {"filters_t": 0, "filters": {}, "clients_t": 0, "clients": {}}

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
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers()), timeout=3) as r:
        return json.loads(r.read().decode())

def api_post(path, payload):
    h = headers()
    h["Content-Type"] = "application/json"
    req = urllib.request.Request(AGH_URL + path, data=json.dumps(payload).encode(), headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=3) as r:
        return json.loads(r.read().decode())

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

def filter_names():
    now = time.time()
    if CACHE["filters_t"] > now:
        return CACHE["filters"]
    names = dict(SPECIAL_LISTS)
    try:
        data = api_get("/control/filtering/status")
        for section in ("filters", "whitelist_filters"):
            for item in data.get(section, []) or []:
                if item.get("id") is not None and item.get("name"):
                    names[str(item["id"])] = str(item["name"])
    except Exception:
        pass
    CACHE["filters"], CACHE["filters_t"] = names, now + 300
    return names

def client_name(ip):
    ip = norm_ip(ip)
    try:
        data = api_post("/control/clients/search", {"clients": [{"id": ip}]})
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    for info in entry.values():
                        if isinstance(info, dict) and info.get("name"):
                            return str(info["name"])
    except Exception:
        pass
    now = time.time()
    if CACHE["clients_t"] <= now:
        names = {}
        try:
            data = api_get("/control/clients")
            for item in data.get("clients", []) or []:
                n = str(item.get("name") or "").strip()
                for ident in item.get("ids", []) or []:
                    if n:
                        names[norm_ip(str(ident))] = n
            for item in data.get("auto_clients", []) or []:
                addr = norm_ip(str(item.get("ip") or ""))
                n = str(item.get("name") or "").strip()
                if addr and n:
                    names[addr] = n
        except Exception:
            pass
        CACHE["clients"], CACHE["clients_t"] = names, now + 120
    if CACHE["clients"].get(ip):
        return CACHE["clients"][ip]
    try:
        n = socket.gethostbyaddr(ip)[0].rstrip(".")
        if n and n != ip:
            return n
    except Exception:
        pass
    return ""

def check(host, client, qtype):
    try:
        d = api_get("/control/filtering/check_host", {"name": host, "client": client, "qtype": qtype})
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}

def details(host, client):
    names = filter_names()
    results = {q: check(host, client, q) for q in ("A", "AAAA")}
    reasons, matches, services, cnames, rewrite_ips = {}, {}, {}, {}, {}
    for qtype, d in results.items():
        reason = str(d.get("reason") or "")
        if reason:
            item = reasons.setdefault(reason, {"text": REASONS.get(reason, reason), "qtypes": set()})
            item["qtypes"].add(qtype)
        service = str(d.get("service_name") or "").strip()
        if service:
            services.setdefault(service, set()).add(qtype)
        cname = str(d.get("cname") or "").strip()
        if cname:
            cnames.setdefault(cname, set()).add(qtype)
        for addr in d.get("ip_addrs", []) or []:
            addr = str(addr or "").strip()
            if addr:
                rewrite_ips.setdefault(addr, set()).add(qtype)
        rules = d.get("rules") or []
        if not rules and d.get("rule"):
            rules = [{"text": d.get("rule"), "filter_list_id": d.get("filter_id")}]
        for rule in rules:
            if isinstance(rule, str):
                text, fid = rule, None
            elif isinstance(rule, dict):
                text = str(rule.get("text") or rule.get("rule") or "")
                fid = rule.get("filter_list_id", rule.get("filter_id"))
            else:
                continue
            list_name = names.get(str(fid), f"Filter #{fid}") if fid is not None else ""
            matches.setdefault((list_name, text), set()).add(qtype)
    return {
        "reasons": [{"code": code, "text": v["text"], "qtypes": sorted(v["qtypes"])} for code, v in reasons.items()] or [{"code": "", "text": "Blocked by network filtering", "qtypes": []}],
        "matches": [{"list": k[0], "rule": k[1], "qtypes": sorted(qtypes)} for k, qtypes in matches.items()],
        "services": [{"name": name, "qtypes": sorted(qtypes)} for name, qtypes in services.items()],
        "cnames": [{"value": value, "qtypes": sorted(qtypes)} for value, qtypes in cnames.items()],
        "rewrite_ips": [{"value": value, "qtypes": sorted(qtypes)} for value, qtypes in rewrite_ips.items()],
        "api_ok": any(bool(x) for x in results.values()),
    }

CSS = r'''
:root{color-scheme:light dark;--bg:#f6f6f3;--card:#fff;--text:#20201e;--muted:#70706b;--line:#deded8;--soft:#f0f0ec;--red:#b42318;--btn:#20201e;--bt:#fff}
@media(prefers-color-scheme:dark){:root{--bg:#111210;--card:#1a1b19;--text:#f1f1ed;--muted:#a4a49d;--line:#343530;--soft:#242521;--red:#ff9188;--btn:#efefe9;--bt:#171715}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}body{margin:0;min-width:280px;min-height:100vh;min-height:100dvh;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{width:min(720px,100%);margin:auto;padding:max(32px,env(safe-area-inset-top)) max(18px,env(safe-area-inset-right)) max(32px,env(safe-area-inset-bottom)) max(18px,env(safe-area-inset-left))}.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:clamp(22px,5vw,36px)}.k{margin:0 0 8px;color:var(--red);font-size:12px;font-weight:750;letter-spacing:.055em;text-transform:uppercase}h1{margin:0;font-size:clamp(30px,7vw,43px);line-height:1.08;letter-spacing:-.025em}.intro{margin:12px 0 23px;color:var(--muted);font-size:16px;line-height:1.5}.domain{padding:14px 15px;background:var(--soft);border:1px solid var(--line);border-radius:10px;font-size:clamp(16px,4vw,19px);font-weight:650;overflow-wrap:anywhere}.summary{margin-top:23px;border-top:1px solid var(--line)}.row{display:grid;grid-template-columns:125px minmax(0,1fr);gap:16px;padding:14px 0;border-bottom:1px solid var(--line)}.label{color:var(--muted);font-size:14px}.value{min-width:0;overflow-wrap:anywhere}.dn{font-weight:650}.dip{margin-top:3px;color:var(--muted);font-size:13px}.matches{margin-top:25px}.matches h2{margin:0 0 9px;font-size:16px}.match{padding:13px 0;border-top:1px solid var(--line)}.ml{font-weight:650}.rule{margin-top:5px;color:var(--muted);font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}.note{margin:17px 0 0;color:var(--muted);font-size:13px;line-height:1.45}.tag{display:inline-block;margin-left:7px;padding:2px 6px;border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:11px;font-weight:600;vertical-align:1px}code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em}button{margin-top:25px;min-height:44px;padding:10px 17px;border:0;border-radius:9px;background:var(--btn);color:var(--bt);font:inherit;font-weight:650;cursor:pointer}.status{min-height:calc(100dvh - 64px);display:grid;align-content:center}@media(max-width:520px){main{padding-left:12px;padding-right:12px}.card{padding:21px 17px;border-radius:13px}.row{grid-template-columns:1fr;gap:4px}}@media(min-width:1000px){main{padding-top:8vh}}
'''

def esc(v): return html.escape(str(v), quote=True)
def page_status(host):
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark"><title>Block page</title><style>{CSS}</style></head><body><main class="status"><section class="card"><p class="k">Block page</p><h1>Service is running</h1><p class="intro">Blocked HTTP destinations can be redirected here by AdGuard Home.</p><div class="domain">{esc(host)}</div></section></main></body></html>'''.encode()
def qt(qtypes): return " + ".join(qtypes) if qtypes else ""
def page_blocked(host, ip, name, d):
    reason_parts=[]
    for item in d["reasons"]:
        label=esc(item["text"]); tech=[]
        if item["code"]: tech.append(esc(item["code"]))
        if item["qtypes"]: tech.append(esc(qt(item["qtypes"])))
        if tech: label += '<div class="dip">' + " · ".join(tech) + '</div>'
        reason_parts.append(label)
    reasons="<br>".join(reason_parts)
    device=f'<div class="dn">{esc(name) if name else "Unknown device"}</div><div class="dip">{esc(ip)}</div>'
    extra=""
    for item in d["services"]:
        q=f' <span class="tag">{esc(qt(item["qtypes"]))}</span>' if item["qtypes"] else ""
        extra += f'<div class="row"><div class="label">Blocked service</div><div class="value">{esc(item["name"])}{q}</div></div>'
    for item in d["cnames"]:
        q=f' <span class="tag">{esc(qt(item["qtypes"]))}</span>' if item["qtypes"] else ""
        extra += f'<div class="row"><div class="label">CNAME rewrite</div><div class="value"><code>{esc(item["value"])}</code>{q}</div></div>'
    if d["rewrite_ips"]:
        parts=[]
        for item in d["rewrite_ips"]:
            q=f' <span class="tag">{esc(qt(item["qtypes"]))}</span>' if item["qtypes"] else ""
            parts.append(f'<code>{esc(item["value"])}</code>{q}')
        extra += f'<div class="row"><div class="label">IP rewrite</div><div class="value">{"<br>".join(parts)}</div></div>'
    match_html=""
    if d["matches"]:
        rows=[]
        for item in d["matches"]:
            list_name=esc(item["list"] or "Filtering rule"); rule=esc(item["rule"] or "Rule text unavailable")
            q=f'<span class="tag">{esc(qt(item["qtypes"]))}</span>' if item["qtypes"] else ""
            rows.append(f'<div class="match"><div class="ml">{list_name}{q}</div><div class="rule">{rule}</div></div>')
        match_html=f'<section class="matches"><h2>Matched rules ({len(d["matches"])})</h2>{"".join(rows)}</section>'
    note="" if d["api_ok"] else '<p class="note">Detailed filter information is temporarily unavailable.</p>'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light dark"><title>Blocked - {esc(host)}</title><style>{CSS}</style></head><body><main><section class="card"><p class="k">Access blocked</p><h1>This site is blocked</h1><p class="intro">The address was stopped by this network's DNS filtering.</p><div class="domain">{esc(host)}</div><div class="summary"><div class="row"><div class="label">Reason</div><div class="value">{reasons}</div></div>{extra}<div class="row"><div class="label">Device</div><div class="value">{device}</div></div></div>{match_html}{note}<button type="button" onclick="history.length>1?history.back():location.replace('about:blank')">Go back</button></section></main></body></html>'''.encode()

class Handler(BaseHTTPRequestHandler):
    def host(self):
        h=(self.headers.get("Host") or "").strip()
        if h.startswith("[") and "]" in h: return h[1:h.index("]")].lower().rstrip(".")
        return h.split(":",1)[0].lower().rstrip(".")
    def common(self, code, body, ctype):
        self.send_response(code); self.send_header("Content-Type",ctype); self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store,max-age=0"); self.send_header("X-Content-Type-Options","nosniff"); self.send_header("X-Frame-Options","DENY"); self.send_header("Referrer-Policy","no-referrer"); self.send_header("Content-Security-Policy","default-src 'none';style-src 'unsafe-inline';script-src 'unsafe-inline';base-uri 'none';frame-ancestors 'none'"); self.end_headers()
    def do_GET(self):
        if self.path=="/healthz":
            body=b'{"ok":true}'; self.common(200,body,"application/json"); self.wfile.write(body); return
        h=self.host()
        if not h or is_ip(h):
            body=page_status(h or "block page"); self.common(200,body,"text/html;charset=utf-8"); self.wfile.write(body); return
        ip=norm_ip(self.client_address[0]); body=page_blocked(h,ip,client_name(ip),details(h,ip)); self.common(451,body,"text/html;charset=utf-8"); self.wfile.write(body)
    def do_HEAD(self):
        if self.path=="/healthz": self.common(200,b"","application/json"); return
        h=self.host(); self.common(200 if (not h or is_ip(h)) else 451,b"","text/html;charset=utf-8")
    def log_message(self,fmt,*args): print(f"{norm_ip(self.client_address[0])} - {fmt % args}",flush=True)

class DualStackServer(ThreadingHTTPServer):
    address_family=socket.AF_INET6; daemon_threads=True; allow_reuse_address=True
    def server_bind(self):
        try: self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
        except OSError: pass
        super().server_bind()

DualStackServer(("::",PORT),Handler).serve_forever()
