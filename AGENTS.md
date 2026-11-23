# Contributor and coding-agent guide

This is a Python standard-library HTTP block page for AdGuard Home, deployed
on Linux with Docker Compose or Portainer. [README.md](README.md) is the public
installation and behavior guide. Keep changes focused on the requested task.

## Repository map

| File | Responsibility |
| --- | --- |
| `app.py` | HTTP listener, device/filter details, and page rendering. |
| `unblock_ui.py` | Client authorization, tokens, same-origin POST handling, and button markup. |
| `unblock.py` | Serialized allowlist updates, backups, cooldown, and persistent pending-state recovery. |
| `memory_guard.py` | Local process, host, and cgroup memory preflight. |
| `docker-compose.yml` | Builds the four runtime modules from local source. |
| `portainer-stack.yml` | Downloads the four modules from one immutable source commit, with startup retries. |
| `scripts/validate.py` | Isolated validation without contacting a real AdGuard instance. |

## Validation

Use Python 3.13 from the repository root:

```sh
python scripts/validate.py
git diff --check
```

The validation script checks syntax, source-pin equality in a Git checkout,
unblock controls, failure on missing memory information, and local IPv4/IPv6
HTTP behavior. It starts and stops its own temporary server.

**Importing `app.py` starts its HTTP listener.** Use the validation script,
static/AST inspection, or an isolated subprocess instead of importing it to
inspect functions or read `APP_VERSION`.

For deployment edits, validate both Compose files using dummy values:

```sh
(
  export AGH_URL=http://192.0.2.10:3000
  export AGH_USERNAME=ci-example AGH_PASSWORD=ci-example
  export UNBLOCK_ALLOWED_NETWORKS=192.0.2.20/32
  export AGH_CONTAINER=example-adguard AGH_DNS_SERVER=192.0.2.10
  docker compose -f docker-compose.yml config --quiet
  docker compose -f portainer-stack.yml config --quiet
)
```

For workflow edits, run this when actionlint is available:

```sh
actionlint .github/workflows/validate.yml .github/workflows/release.yml
```

CI also checks alternate deployment values and builds/smoke-tests the Docker
image. State which checks actually ran; configuration parsing is not a
container runtime test. There is no npm, pytest, or frontend dependency-install
step.

## Runtime and configuration boundaries

- Use temporary state, placeholder credentials, and isolated listeners in
  checks. Repository validation must not mutate a real AdGuard instance.
- Preserve client-bound tokens, same-origin checks, and server-side credentials.
  Unblock applies to the hostname and its subdomains for all AdGuard clients.
- Preserve the documented authorization behavior: detected global IPv6 on-link
  networks are included in addition to `UNBLOCK_ALLOWED_NETWORKS`. Do not
  describe that variable alone as an exclusive IPv6 administrator allowlist.
- Preserve same-host memory verification, two samples, conservative headroom,
  serialized updates, backups, cooldown, and persistent pending state. Missing
  or ambiguous information must decline the operation. Never automatically
  replay an uncertain write or delete pending state to make a test pass.
- Preserve read-only host status mounts, host cgroup namespace, and the state
  volume. The deployment does not use a Docker socket or restart AdGuard.
- The page is HTTP only. Do not claim HTTPS interception, guaranteed memory
  safety, exhaustive blocklist enumeration, or guaranteed client MAC discovery.
  `/healthz` measures listener liveness, not AdGuard/DNS integration.

## Immutable runtime source and releases

The Portainer stack must download `app.py`, `unblock.py`, `unblock_ui.py`, and
`memory_guard.py` from one full commit SHA. Those files must be byte-for-byte
identical to the selected release's modules. Do not replace the pin with `main`
or a floating download URL.

When runtime modules change, first commit their intended contents. Then update
the source SHA in `portainer-stack.yml` and the matching assertion in
`.github/workflows/validate.yml` to that commit, and run `scripts/validate.py`.
Documentation-only edits do not need a runtime version bump or a changed pin.

Release tags must match `APP_VERSION`. Retain exact-SHA verification and all
validation dependencies in `.github/workflows/release.yml`; do not overwrite
published assets or remove checks to obtain a release.

## Public documentation

Use adaptable examples and label documentation-only IP addresses. Keep real
credentials, client identities, and browsing data out of tracked files. Describe
actual Linux/Compose/Portainer requirements and observed limitations. Keep
contributor guidance here; the short Copilot file points back to this guide.
