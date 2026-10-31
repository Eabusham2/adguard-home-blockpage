"""Serialized AdGuard Home allowlist updates; never starts/restarts AdGuard.

set_rules replaces all custom rules and rebuilds AdGuard's filter engines.
The memory preflight is conservative, not a proof that a rebuild cannot OOM.
An uncertain write stays recorded on disk and is never automatically retried.
"""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import threading
import time
from urllib.error import HTTPError

from memory_guard import MemoryGuardError, check_memory_headroom

SUCCESS_MESSAGE = (
    "Unblocked. Refresh the page. Your device may still be using the old DNS "
    "result. If this page appears again, wait a little and refresh again."
)
PENDING_MESSAGE = (
    "The whitelist request is awaiting confirmation from AdGuard. Wait a little, "
    "then refresh the page. It will not be submitted again automatically."
)
MAX_STATE_BYTES = 2 * 1024 * 1024
COOLDOWN_SECONDS = 120
VERIFY_SECONDS = 30
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class UnblockError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def normalize_host(value):
    if not isinstance(value, str) or len(value) > 1024:
        raise UnblockError(400, "This address is not a valid hostname.")
    if value != value.strip() or any(c in value for c in "/\\:@$^*\r\n\t "):
        raise UnblockError(400, "This address is not a valid hostname.")
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise UnblockError(400, "This address is not a valid hostname.") from None
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or not all(LABEL.fullmatch(x) for x in labels):
        raise UnblockError(400, "Only a complete domain name can be unblocked.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise UnblockError(400, "IP addresses cannot be added as domain exceptions.")


def rule_texts(result):
    texts = []
    for item in result.get("rules") or []:
        if isinstance(item, dict):
            texts.append(str(item.get("text") or item.get("rule") or ""))
        elif isinstance(item, str):
            texts.append(item)
    if result.get("rule"):
        texts.append(str(result["rule"]))
    return texts


def is_allowlisted(result, expected_rule=None):
    # check_host has no is_filtered field.  This is its actual wire spelling.
    if result.get("reason") != "NotFilteredWhiteList":
        return False
    texts = rule_texts(result)
    return expected_rule in texts if expected_rule else any(x.startswith("@@") for x in texts)


def currently_open(results):
    return len(results) == 2 and all(
        r.get("reason") == "NotFilteredNotFound" or is_allowlisted(r) for r in results
    )


class UnblockBackend:
    def __init__(self, api_get, api_post, agh_url, state_dir="/state", memory_check=None):
        self.get = api_get
        self.post = api_post
        self.agh_url = agh_url
        self.state_dir = Path(state_dir)
        self.memory_check = memory_check or check_memory_headroom
        self.lock = threading.Lock()

    def _read_state(self):
        p = self.state_dir / "unblock-state.json"
        if not p.exists():
            return {"pending": None, "next_write_after": 0}
        with p.open("rb") as f:
            raw = f.read(MAX_STATE_BYTES + 1)
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError("State file too large")
        state = json.loads(raw)
        if not isinstance(state, dict) or not isinstance(state.get("next_write_after"), (int, float)):
            raise ValueError("Invalid state")
        pending = state.get("pending")
        if pending is not None:
            if not isinstance(pending, dict):
                raise ValueError("Invalid pending operation")
            normalize_host(pending.get("host"))
            if (not isinstance(pending.get("client"), str)
                    or not isinstance(pending.get("additions"), list)
                    or not 1 <= len(pending["additions"]) <= 2
                    or not all(isinstance(x, str) for x in pending["additions"])):
                raise ValueError("Invalid pending operation")
        return state

    def _write_json(self, name, data):
        raw = json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode()
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError("State file too large")
        temp = self.state_dir / (name + ".tmp")
        with temp.open("wb") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, self.state_dir / name)
        directory = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _rules(self):
        data = self.get("/control/filtering/status")
        if not isinstance(data, dict) or "user_rules" not in data:
            raise UnblockError(502, "AdGuard did not return its existing rules. Nothing was changed.")
        rules = data["user_rules"]
        if rules is None:
            rules = []
        if not isinstance(rules, list) or not all(isinstance(x, str) for x in rules):
            raise UnblockError(502, "AdGuard returned invalid custom rules. Nothing was changed.")
        if data.get("enabled") is False:
            raise UnblockError(409, "AdGuard filtering is disabled. No whitelist change was made.")
        return rules

    def _checks(self, host, client):
        results = [self.get("/control/filtering/check_host", {
            "name": host, "client": client, "qtype": qtype,
        }) for qtype in ("A", "AAAA")]
        if not all(isinstance(x, dict) and isinstance(x.get("reason"), str) for x in results):
            raise UnblockError(502, "AdGuard could not verify this hostname.")
        return results

    def _active(self, host, client, expected_rule):
        results = self._checks(host, client)
        # One qtype may legitimately select another equally important exception.
        # Both must be allowed, and the new engine must demonstrate our rule.
        return all(is_allowlisted(x) for x in results) and any(
            is_allowlisted(x, expected_rule) for x in results
        )

    def _finish(self, state):
        state["pending"] = None
        state["next_write_after"] = time.time() + COOLDOWN_SECONDS
        self._write_json("unblock-state.json", state)

    def _recover_pending(self, state):
        pending = state.get("pending")
        if not pending:
            return
        rules = self._rules()
        if all(x in rules for x in pending["additions"]) and self._active(
            pending["host"], pending["client"], f"@@||{pending['host']}^$important"
        ):
            self._finish(state)
            return
        raise UnblockError(409,
            "An earlier whitelist update is still unconfirmed. No new update was sent. "
            "Wait and refresh; if it persists, check AdGuard before trying another site.")

    def run(self, host, client):
        host = normalize_host(host)
        if not self.agh_url:
            raise UnblockError(503, "AdGuard access has not been configured.")
        if not self.lock.acquire(blocking=False):
            raise UnblockError(409, "Another unblock is still being applied. Please wait and refresh.")
        lock_file = None
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            lock_file = (self.state_dir / "unblock.lock").open("a+b")
            os.fchmod(lock_file.fileno(), 0o600)
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise UnblockError(409, "Another unblock is still being applied. Please wait.") from None
            state = self._read_state()
            # Recovery only reads AdGuard; it never replays a possibly accepted POST.
            self._recover_pending(state)
            existing = self._rules()
            checks = self._checks(host, client)
            if currently_open(checks):
                return {"ok": True, "message": SUCCESS_MESSAGE, "already_allowed": True}
            if any(r.get("reason") in ("Rewrite", "RewriteEtcHosts") for r in checks):
                raise UnblockError(422,
                    "This address has a DNS rewrite or hosts-file override. It must be changed "
                    "in AdGuard before a whitelist rule can unblock it. Nothing was changed.")
            rule = f"@@||{host}^$important"
            additions = [rule]
            if any(r.get("reason") == "RewriteRule" or any(
                "$dnsrewrite" in t or ",dnsrewrite" in t for t in rule_texts(r)
            ) for r in checks):
                additions.append(f"@@||{host}^$dnsrewrite")
            missing = [x for x in additions if x not in existing]
            if not missing:
                raise UnblockError(409,
                    "This site is already in the whitelist, but AdGuard has not confirmed it is "
                    "active. No duplicate update was sent. Wait and refresh the page.")
            wait = state["next_write_after"] - time.time()
            if wait > 0:
                raise UnblockError(429,
                    f"AdGuard is settling after the last change. Wait {int(wait) + 1} seconds, "
                    "then try Unblock again. Nothing was changed.")
            try:
                metrics = self.memory_check(self.agh_url)
            except MemoryGuardError as e:
                print("Unblock memory preflight declined: " + str(e), flush=True)
                raise UnblockError(503,
                    "Unblock paused: there is not enough verified memory headroom for AdGuard. "
                    "Nothing was changed. Try again later, or check the block-page container log.") from None
            # The API has no compare-and-swap; catch edits that happened during preflight.
            if self._rules() != existing:
                raise UnblockError(409,
                    "AdGuard's rules changed during this request. Nothing was overwritten. "
                    "Refresh the page and try again.")
            intended = existing + missing
            if len(json.dumps({"rules": intended}).encode()) > MAX_STATE_BYTES - 2048:
                raise UnblockError(413, "The custom-rule list is too large for this button. Nothing was changed.")
            self._write_json("user-rules-backup.json", {"saved_at": time.time(), "user_rules": existing})
            state["pending"] = {
                "host": host, "client": client, "additions": additions,
                "started_at": time.time(), "stage": "write_may_have_been_sent",
            }
            self._write_json("unblock-state.json", state)
            print("Unblock preflight passed: " + json.dumps(metrics, sort_keys=True), flush=True)
            try:
                # Exactly one write. A timeout is ambiguous and is NEVER retried here.
                self.post("/control/filtering/set_rules", {"rules": intended})
            except HTTPError as e:
                if e.code in (400, 401, 403, 404, 405, 413, 415):
                    # These are definite request/auth/routing rejections, not a
                    # dropped response or uncertain server-side write failure.
                    self._finish(state)
                    raise UnblockError(502,
                        "AdGuard rejected the whitelist request. Check the configured AdGuard "
                        "access and container log. The request will not be retried automatically.") from None
                print("Unblock API outcome uncertain: HTTP " + str(e.code), flush=True)
                return {"ok": False, "pending": True, "message": PENDING_MESSAGE}
            except Exception as e:
                print("Unblock API outcome uncertain: " + type(e).__name__, flush=True)
                return {"ok": False, "pending": True, "message": PENDING_MESSAGE}
            deadline = time.monotonic() + VERIFY_SECONDS
            while True:
                try:
                    # A saved custom-rule array alone is not proof the new engine is active.
                    current = self._rules()
                    active = all(x in current for x in additions) and self._active(host, client, rule)
                except Exception:
                    active = False
                if active:
                    self._finish(state)
                    cache_cleared = False
                    try:
                        self.post("/control/cache_clear", {})
                        cache_cleared = True
                    except Exception as e:
                        print("Whitelist active; cache-clear failed: " + type(e).__name__, flush=True)
                    return {"ok": True, "message": SUCCESS_MESSAGE, "cache_cleared": cache_cleared}
                if time.monotonic() >= deadline:
                    return {"ok": False, "pending": True, "message": PENDING_MESSAGE}
                time.sleep(2)
        except UnblockError:
            raise
        except Exception as e:
            # Do not disclose URLs, credentials, request headers, or the custom-rule list.
            print("Unblock stopped: " + type(e).__name__, flush=True)
            raise UnblockError(503,
                "The whitelist change could not be confirmed. No automatic retry will run. "
                "Check AdGuard and the block-page container log before trying again.") from None
        finally:
            if lock_file is not None:
                lock_file.close()
            self.lock.release()
