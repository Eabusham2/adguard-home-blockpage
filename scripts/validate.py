#!/usr/bin/env python3
"""Offline release checks; never contacts or changes a real AdGuard instance."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MODULES = ("app.py", "unblock.py", "unblock_ui.py", "memory_guard.py")


def main():
    for name in MODULES:
        compile((ROOT / name).read_bytes(), name, "exec")

    # A pinned source download must run exactly the code in the selected release.
    stack = (ROOT / "portainer-stack.yml").read_text()
    match = re.search(r"SRC=https://raw\.githubusercontent\.com/"
                      r"Eabusham2/adguard-home-blockpage/([0-9a-f]{40})", stack)
    assert match, "Portainer source must be pinned to a full commit SHA"
    if (ROOT / ".git").exists():
        for name in MODULES:
            pinned = subprocess.check_output(
                ["git", "show", f"{match[1]}:{name}"], cwd=ROOT
            )
            assert pinned == (ROOT / name).read_bytes(), f"Source pin differs: {name}"

    with tempfile.TemporaryDirectory(prefix="blockpage-check-") as directory:
        os.environ["UNBLOCK_ALLOWED_NETWORKS"] = "192.0.2.20/32,127.0.0.0/8,::1/128"
        os.environ["UNBLOCK_HOST_PROC"] = directory
        os.environ["UNBLOCK_STATE_DIR"] = directory
        os.environ["AGH_URL"] = "http://127.0.0.1:1"
        sys.path.insert(0, str(ROOT))
        import unblock_ui
        from unblock import normalize_host
        from memory_guard import MemoryGuardError, check_memory_headroom

        assert normalize_host("Example.COM") == "example.com"
        assert unblock_ui.client_may_unblock("192.0.2.20")
        assert not unblock_ui.client_may_unblock("192.0.2.21")
        assert not unblock_ui.client_may_unblock("8.8.8.8")
        markup = unblock_ui.render_controls("example.com", "192.0.2.20")
        assert 'id="unblock"' in markup and 'data-token="' in markup
        assert "Refresh page" in unblock_ui.render_controls("example.com", "192.0.2.20", True)
        token = unblock_ui.csrf_token("example.com", "192.0.2.20")
        assert unblock_ui.valid_token(token, "example.com", "192.0.2.20")
        assert not unblock_ui.valid_token(token, "example.org", "192.0.2.20")
        assert not unblock_ui.valid_token(token, "example.com", "192.0.2.21")
        assert not unblock_ui.valid_token("bogus", "example.com", "192.0.2.20")
        try:
            check_memory_headroom("http://127.0.0.1", _proc_root=directory,
                                  _cgroup_root=directory)
        except MemoryGuardError:
            pass
        else:
            raise AssertionError("Missing memory information must fail closed")

        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", 0))
            port = probe.getsockname()[1]
        environment = dict(os.environ, PORT=str(port), PYTHONDONTWRITEBYTECODE="1")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        process = subprocess.Popen([sys.executable, "app.py"], cwd=ROOT,
                                   env=environment, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                try:
                    with opener.open(f"http://127.0.0.1:{port}/healthz", timeout=1) as response:
                        assert response.status == 200
                        assert json.loads(response.read()) == {"ok": True}
                    break
                except urllib.error.URLError:
                    if process.poll() is not None:
                        raise AssertionError(process.stderr.read().decode())
                    time.sleep(0.1)
            else:
                raise AssertionError("HTTP server did not become healthy")
            for address in ("127.0.0.1", "[::1]"):
                with opener.open(f"http://{address}:{port}/", timeout=2) as response:
                    assert response.status == 200
                    assert "Location" not in response.headers
                    assert b"The service is running" in response.read()
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
    print("Python syntax, source pin, unblock controls, fail-closed memory check, "
          "and IPv4/IPv6 HTTP smoke checks passed")


if __name__ == "__main__":
    main()
