"""Conservative, read-only memory preflight for a local AdGuard Home update.

Deploy with host networking, the host cgroup namespace, and read-only mounts of
/proc at /host-proc and /sys/fs/cgroup at /host-cgroup.  No Docker socket, process
restart, signal, memory-control write, DNS lookup, or outgoing connection is used.

This is a heuristic, NOT an OOM guarantee or a memory reservation.  AdGuard can
allocate more than its present footprint while rebuilding filters; unrelated
processes can also allocate after the check.  The caller must serialize updates,
check API readiness separately, and avoid automatically retrying mutations.

The guard requires room for another current AdGuard memory footprint plus
256 MiB, with an additional 256 MiB of host reserve and 128 MiB below every
finite cgroup hard/high/memory+swap boundary.  It rejects unavailable or ambiguous
measurements and rapid growth between two samples one second apart.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path, PurePosixPath
import re
import socket
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit


MIB = 1024 * 1024
MAX_PROC_ENTRIES = 65536
MAX_PROCESSES = 32768
UNLIMITED_V1 = 1 << 60


class MemoryGuardError(RuntimeError):
    """The guard could not establish sufficient memory headroom."""


@dataclass(frozen=True)
class _Boundary:
    key: str
    usage: int
    limit: int


@dataclass(frozen=True)
class _Snapshot:
    pid: int
    start_ticks: int
    rss: int
    cg_usage: int
    host_available: int
    identity: tuple[str, str, str]
    boundaries: tuple[_Boundary, ...]


def _text(path: Path, limit: int = 65536) -> str:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise MemoryGuardError("A memory-status file exceeded its safe size limit.")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise MemoryGuardError("A memory-status file could not be understood.") from None


def _number(text: str) -> int:
    value = text.strip()
    if not re.fullmatch(r"[0-9]{1,20}", value):
        raise MemoryGuardError("The host returned an invalid memory measurement.")
    number = int(value)
    if number >= 1 << 64:
        raise MemoryGuardError("The host returned an invalid memory measurement.")
    return number


def _bytes_field(text: str, field: str) -> int:
    matches = re.findall(rf"^{re.escape(field)}:\s+([0-9]+)\s+kB\s*$", text, re.M)
    if len(matches) != 1:
        raise MemoryGuardError("Required host memory information is unavailable.")
    return _number(matches[0]) * 1024


def _verify_local_api(agh_url: str) -> None:
    """Check locality using a local UDP bind; never resolve or connect."""
    try:
        parsed = urlsplit(agh_url)
        hostname = parsed.hostname
        port = parsed.port
        if (
            parsed.scheme not in ("http", "https")
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError
        if hostname == "localhost":
            address = ipaddress.ip_address("127.0.0.1")
        else:
            # A hostname or zone-id would require an additional resolution path.
            if "%" in hostname:
                raise ValueError
            address = ipaddress.ip_address(hostname)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if address.is_unspecified or address.is_multicast:
            raise ValueError
    except (ValueError, TypeError):
        raise MemoryGuardError(
            "Memory protection requires AGH_URL to use this host's literal IP "
            "address or localhost, without credentials in the URL."
        ) from None
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            probe.bind((str(address), 0))
    except OSError:
        raise MemoryGuardError(
            "The AdGuard API address is not available on this host; "
            "its memory cannot be checked safely."
        ) from None


def _process(proc_root: Path) -> tuple[int, int, int, str]:
    candidates: list[int] = []
    count = 0
    entries = 0
    with os.scandir(proc_root) as directory:
        for entry in directory:
            entries += 1
            if entries > MAX_PROC_ENTRIES:
                raise MemoryGuardError("The host process list exceeded its safe scan limit.")
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            count += 1
            if count > MAX_PROCESSES:
                raise MemoryGuardError("The host process list exceeded its safe scan limit.")
            try:
                name = _text(proc_root / entry.name / "comm", 256).strip()
            except (FileNotFoundError, ProcessLookupError):
                continue  # An unrelated process may exit during the scan.
            if name == "AdGuardHome":
                candidates.append(int(entry.name))
                if len(candidates) > 1:
                    raise MemoryGuardError(
                        "More than one AdGuard Home process is running; "
                        "memory protection cannot identify the correct instance."
                    )
    if len(candidates) != 1:
        raise MemoryGuardError(
            "The running AdGuard Home process could not be identified. "
            "Check the read-only host status mounts."
        )
    pid = candidates[0]
    base = proc_root / str(pid)
    status = _text(base / "status")
    rss = _bytes_field(status, "VmRSS")
    if rss <= 0:
        raise MemoryGuardError("AdGuard Home has no usable resident-memory measurement.")
    stat = _text(base / "stat", 16384)
    # The parenthesized comm field can contain spaces and ')' characters.
    suffix = stat.rsplit(")", 1)
    if len(suffix) != 2:
        raise MemoryGuardError("AdGuard Home's process identity could not be checked.")
    fields = suffix[1].split()
    if len(fields) < 20:
        raise MemoryGuardError("AdGuard Home's process identity could not be checked.")
    start_ticks = _number(fields[19])  # Field 22; suffix begins at field 3.
    return pid, start_ticks, rss, _text(base / "cgroup", 32768)


def _absolute_path(value: str) -> PurePosixPath:
    if (
        not value.startswith("/")
        or len(value) > 4096
        or "\x00" in value
        or "\n" in value
        or any(part in (".", "..") for part in value.split("/"))
    ):
        raise MemoryGuardError("The host reported an unsupported cgroup path.")
    return PurePosixPath(value)


def _unescape_mount(value: str) -> str:
    result = re.sub(
        r"\\(040|011|012|134)",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )
    # A path containing a newline or NUL cannot be parsed safely here.
    if "\n" in result or "\x00" in result:
        raise MemoryGuardError("The host reported an unsupported cgroup mount.")
    return result


def _membership(text: str) -> tuple[str, PurePosixPath]:
    v1: list[PurePosixPath] = []
    v2: list[PurePosixPath] = []
    for line in text.splitlines():
        fields = line.split(":", 2)
        if len(fields) != 3:
            raise MemoryGuardError("AdGuard Home's cgroup membership is invalid.")
        identifier, controllers, path = fields
        if "memory" in controllers.split(","):
            v1.append(_absolute_path(path))
        elif identifier == "0" and controllers == "":
            v2.append(_absolute_path(path))
    # In a hybrid hierarchy, v1 owns memory if it explicitly lists it.
    if len(v1) == 1:
        return "v1", v1[0]
    if len(v1) > 1 or len(v2) != 1:
        raise MemoryGuardError("AdGuard Home's memory hierarchy is unavailable or ambiguous.")
    return "v2", v2[0]


def _mount(proc_root: Path, cg_root: Path, version: str) -> Path:
    candidates: set[PurePosixPath] = set()
    expected_prefix = PurePosixPath("/sys/fs/cgroup")
    for line in _text(proc_root / "1" / "mountinfo", 512 * 1024).splitlines():
        halves = line.split(" - ", 1)
        if len(halves) != 2:
            continue
        left, right = halves[0].split(), halves[1].split()
        if len(left) < 6 or len(right) < 3:
            continue
        fstype = right[0]
        is_match = fstype == "cgroup2" if version == "v2" else (
            fstype == "cgroup" and "memory" in right[2].split(",")
        )
        if not is_match:
            continue
        mountpoint = _absolute_path(_unescape_mount(left[4]))
        try:
            relative = mountpoint.relative_to(expected_prefix)
        except ValueError:
            continue
        if _absolute_path(_unescape_mount(left[3])) != PurePosixPath("/"):
            # A delegated subtree hides limits imposed by higher ancestors.
            continue
        candidates.add(relative)
    if len(candidates) != 1:
        raise MemoryGuardError(
            "The complete host memory hierarchy could not be inspected. "
            "Check the read-only cgroup mount and host cgroup namespace."
        )
    return cg_root.joinpath(*next(iter(candidates)).parts)


def _limit(path: Path, version: str) -> int | None:
    raw = _text(path, 128).strip()
    if version == "v2" and raw == "max":
        return None
    value = _number(raw)
    if version == "v1" and value >= UNLIMITED_V1:
        return None
    return value


def _cgroup(
    proc_root: Path, cg_root: Path, membership: str,
) -> tuple[int, tuple[str, str, str], tuple[_Boundary, ...]]:
    version, relative = _membership(membership)
    mount = _mount(proc_root, cg_root, version)
    leaf = mount.joinpath(*relative.parts[1:])
    # Resolve symlinks while ensuring no configured mount/path escapes its root.
    try:
        mount_real = mount.resolve(strict=True)
        root_real = cg_root.resolve(strict=True)
        mount_real.relative_to(root_real)
        leaf_real = leaf.resolve(strict=True)
        leaf_real.relative_to(mount_real)
    except (OSError, ValueError):
        raise MemoryGuardError("The host memory hierarchy is incomplete or inaccessible.") from None

    boundaries: list[_Boundary] = []
    leaf_usage = 0
    current = leaf_real
    while True:
        at_root = current == mount_real
        key = current.relative_to(mount_real).as_posix()
        if version == "v2":
            usage_path = current / "memory.current"
            if at_root and not usage_path.exists():
                # The true v2 root has no memory.current/max/high interface.
                controllers = _text(current / "cgroup.controllers", 4096).split()
                if "memory" not in controllers:
                    raise MemoryGuardError("The host memory controller is unavailable.")
                usage = 0
            else:
                usage = _number(_text(usage_path, 128))
                for filename in ("memory.max", "memory.high"):
                    path = current / filename
                    if at_root and not path.exists():
                        continue
                    value = _limit(path, version)
                    if value is not None:
                        boundaries.append(_Boundary(key + ":" + filename, usage, value))
        else:
            usage = _number(_text(current / "memory.usage_in_bytes", 128))
            value = _limit(current / "memory.limit_in_bytes", version)
            if value is not None:
                boundaries.append(_Boundary(key + ":memory", usage, value))
            swap_limit = current / "memory.memsw.limit_in_bytes"
            swap_usage = current / "memory.memsw.usage_in_bytes"
            if swap_limit.exists() != swap_usage.exists():
                raise MemoryGuardError("The host memory-and-swap information is incomplete.")
            if swap_limit.exists():
                value = _limit(swap_limit, version)
                if value is not None:
                    used = _number(_text(swap_usage, 128))
                    boundaries.append(_Boundary(key + ":memory+swap", used, value))
        if current == leaf_real:
            leaf_usage = usage
        if at_root:
            break
        current = current.parent
    return leaf_usage, (version, str(relative), str(mount_real)), tuple(boundaries)


def _sample(proc_root: Path, cg_root: Path) -> _Snapshot:
    pid, ticks, rss, membership = _process(proc_root)
    meminfo = _text(proc_root / "meminfo")
    available = _bytes_field(meminfo, "MemAvailable")
    total = _bytes_field(meminfo, "MemTotal")
    if total <= 0 or not 0 <= available <= total:
        raise MemoryGuardError("Host available memory could not be checked reliably.")
    usage, identity, boundaries = _cgroup(proc_root, cg_root, membership)
    return _Snapshot(pid, ticks, rss, usage, available, identity, boundaries)


def check_memory_headroom(
    agh_url: str,
    *,
    _proc_root: str | os.PathLike[str] = "/host-proc",
    _cgroup_root: str | os.PathLike[str] = "/host-cgroup",
    _sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Return non-secret metrics, or raise before any whitelist mutation.

    Private keyword arguments are provided for deterministic filesystem fixtures.
    Insufficient permissions, missing counters, inconsistent hierarchies and a
    changing AdGuard process all fail closed.  Error messages contain no URLs,
    credentials, command lines, environment values, or filesystem contents.
    """
    _verify_local_api(agh_url)
    try:
        proc_root, cg_root = Path(_proc_root), Path(_cgroup_root)
        first = _sample(proc_root, cg_root)
        _sleep(1.0)
        second = _sample(proc_root, cg_root)
    except MemoryGuardError:
        raise
    except (OSError, ValueError, IndexError):
        raise MemoryGuardError(
            "AdGuard Home's memory information is unavailable or changed during "
            "the check. No whitelist update was started."
        ) from None

    if (first.pid, first.start_ticks, first.identity) != (
        second.pid, second.start_ticks, second.identity
    ):
        raise MemoryGuardError("AdGuard Home is restarting or changing; try again after it settles.")
    for before, after in ((first.rss, second.rss), (first.cg_usage, second.cg_usage)):
        if after - before > max(32 * MIB, before // 20):
            raise MemoryGuardError("AdGuard Home's memory use is still growing; try again after it settles.")
    first_limits = {entry.key: entry.limit for entry in first.boundaries}
    second_limits = {entry.key: entry.limit for entry in second.boundaries}
    if first_limits != second_limits:
        raise MemoryGuardError("AdGuard Home's memory limits changed during the check; try again later.")

    footprint = max(first.rss, second.rss, first.cg_usage, second.cg_usage)
    extra_required = footprint + 256 * MIB
    available = min(first.host_available, second.host_available)
    if available < extra_required + 256 * MIB:
        raise MemoryGuardError(
            "Not enough free RAM to safely attempt a filter update. "
            "The website is still blocked; try again after memory use falls."
        )
    headrooms = [entry.limit - entry.usage for entry in first.boundaries + second.boundaries]
    cgroup_available = min(headrooms) if headrooms else None
    if cgroup_available is not None and cgroup_available < extra_required + 128 * MIB:
        raise MemoryGuardError(
            "AdGuard Home is too close to a container or parent memory limit. "
            "No whitelist update was started."
        )
    return {
        "ok": True,
        "pid": second.pid,
        "cgroup_version": second.identity[0],
        "rss_mib": round(max(first.rss, second.rss) / MIB, 1),
        "cgroup_usage_mib": round(max(first.cg_usage, second.cg_usage) / MIB, 1),
        "host_available_mib": round(available / MIB, 1),
        "extra_required_mib": round(extra_required / MIB, 1),
        "cgroup_headroom_mib": None if cgroup_available is None else round(cgroup_available / MIB, 1),
        "host_reserve_mib": 256,
        "cgroup_reserve_mib": 128,
        "samples": 2,
    }
