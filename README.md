# AdGuard Home Block Page

An open-source custom HTTP block page for AdGuard Home. Explain why a
DNS-blocked website was blocked, display available device and filtering
details, and let permitted LAN clients request an allowlist exception.
Self-host it on Linux with Docker Compose or Portainer; no particular router
brand is required.

[Download a release](https://github.com/Eabusham2/adguard-home-blockpage/releases)
· [Report a problem](https://github.com/Eabusham2/adguard-home-blockpage/issues)

[Docker Compose setup](#quick-start-with-docker-compose)
· [Portainer setup](#portainer-installation)
· [FAQ](#frequently-asked-questions)
· [Troubleshooting](#troubleshooting)
· [Support](#support)
· [Development](#development-and-releases)

## What it does

- Listens on IPv4 and IPv6 and retains the original blocked HTTP hostname.
- Shows device names and addresses from AdGuard, reverse DNS, and available
  neighbor information. MAC addresses appear only when they can be determined.
- Combines A and AAAA filtering results with available local query-log records.
- Labels matching custom rules and reports applied blocklist rules, blocked
  services, CNAMEs, and DNS rewrites.
- Provides a compact layout that follows the browser's light/dark preference.
- Shows service status on direct-IP visits and exposes `/healthz` for monitoring.
- Lets permitted clients request an AdGuard exception for a hostname and its
  subdomains, affecting every device using that AdGuard instance.

The page renders in place; it does **not** redirect to a different origin.
JavaScript is used for the Unblock and Refresh buttons. The explanation itself
is server-rendered.

## Requirements and limits

- Linux with Docker Engine and a modern Docker Compose plugin that accepts
  `cgroup: host`; Portainer must use a Docker Standalone environment, not Swarm.
- An existing AdGuard Home installation with API access and credentials when
  API authentication is enabled.
- IPv6 socket support on the host; the server uses a dual-stack `::` listener
  for both IPv4 and IPv6 requests.
- Port 80 available on the block-page host. Move another web service or use a
  different host if that port is already occupied.
- Clients must actually use AdGuard for DNS. Browser Secure DNS, another DNS
  server, or a VPN can bypass its answers.
- For **Unblock**, AdGuard must run on the same Linux host, with exactly one
  detectable `AdGuardHome` process. `AGH_URL` must use that host's literal IP
  address or `localhost`. A remote AdGuard can supply page details, but its
  memory cannot be verified for an unblock operation.

**HTTPS:** this service does not intercept TLS. HTTPS-only sites, HSTS, and
HTTPS-first browser behavior may show a connection/certificate error instead
of this page. Test with an explicit `http://` URL; a Custom IP DNS response
cannot transparently replace an arbitrary HTTPS site.

AdGuard's filtering API reports applied rules, not every subscribed list that
contains a domain. The app also checks available custom rules and local query
logs; it does not download and scan all blocklists.

## Quick start with Docker Compose

1. Download and extract a release source bundle, or clone this repository and
   check out the release tag you intend to run.
2. Copy the example environment file and replace its values:

   ```sh
   cp .env.example .env
   chmod 600 .env
   ```

   The `192.0.2.x` addresses in the example are documentation placeholders,
   **not usable LAN defaults**. Use your host address, API port, credentials,
   and trusted administrator addresses. If a password contains `$`, enclose
   the whole value in single quotes in the Compose `.env` file.

3. Validate and start the service:

   ```sh
   docker compose config --quiet
   docker compose up -d --build
   docker compose ps
   ```

4. Open `http://<block-page-host-ip>/` and confirm the status page appears.
   `http://<block-page-host-ip>/healthz` should return `{"ok":true}`. This proves
   the web service is running; it does not check AdGuard credentials or filtering.
5. Configure AdGuard as described below, then test an HTTP hostname that your
   AdGuard rules already block.

The default [docker-compose.yml](docker-compose.yml) builds the four Python
modules from your selected source release. Host networking preserves the real
client address. The filesystem is read-only except for temporary files and the
named `unblock_state` volume.

For richer local query-log/configuration details, add read-only mounts for your
AdGuard data paths and set `AGH_QUERYLOG_FILE` / `AGH_CONFIG_FILE` accordingly.
These file reads are optional; the default Compose deployment uses the API.

## Portainer installation

Use [portainer-stack.yml](portainer-stack.yml) in **Stacks → Add stack** on the
same Linux Docker host as the existing AdGuard container. Set the environment
variables below in Portainer before deploying. This stack does not create,
replace, or restart the AdGuard container.

| Variable | Meaning |
| --- | --- |
| `AGH_URL` | AdGuard API base URL, for example `http://192.0.2.10:3000` after replacing the address. |
| `AGH_USERNAME` | Existing AdGuard account username; may be blank when API authentication is disabled. |
| `AGH_PASSWORD` | Existing AdGuard account password; may be blank with authentication disabled. Keep real credentials out of Git. |
| `UNBLOCK_ALLOWED_NETWORKS` | Comma-separated trusted IPv4/IPv6 CIDRs; see the authorization notes below. Required by both deployment files. |
| `AGH_CONTAINER` | **Portainer only:** exact name of the existing AdGuard container, used for read-only volume inheritance. |
| `AGH_DNS_SERVER` | **Portainer only:** reachable DNS server used to download the pinned source, usually your AdGuard DNS address. |
| `FALLBACK_DNS_SERVER` | **Portainer only:** fallback resolver during an AdGuard outage; defaults to `1.1.1.1`. Set a resolver permitted by your network policy. |
| `AGH_QUERYLOG_FILE` | **Portainer only:** path inside the inherited volumes; defaults to `/opt/adguardhome/work/data/querylog.json`. |
| `AGH_CONFIG_FILE` | **Portainer only:** path inside the inherited volumes; defaults to `/opt/adguardhome/conf/AdGuardHome.yaml`. |

The Portainer stack uses `python:3.13-alpine`, downloads all four modules from
one immutable Git commit, retries temporary download failures, and checks Python
syntax before starting. It downloads again after container recreation/restart,
so GitHub access and working DNS are required at startup. The Docker Compose
build is the alternative when startup must not depend on a source download.

The pinned modules are byte-for-byte identical to those in this source release.
The Python base image is a version tag, not a digest; the release does not claim
a fully reproducible container image.

## Configure AdGuard Home

In AdGuard Home, choose **Custom IP** for the DNS blocking mode. Set the blocked
IPv4 response to the block-page host's reachable IPv4 address. On a dual-stack
network, configure the blocked IPv6 response to that host's reachable IPv6
address as well. Port 80 must be accessible from the client networks.

Verify both A and AAAA answers and then visit an explicitly HTTP blocked URL.
A direct-IP status page confirms only the web listener; the blocked hostname
request supplies the domain needed to display filtering details.

## Unblock permissions and persistence

Unblock adds an allowlist exception for the displayed hostname and its
subdomains for **all clients**, rather than only the device clicking the button.
Treat allowed networks as an administrative privilege. Keep this HTTP service
on a trusted LAN and do not forward it to the Internet.

Set `UNBLOCK_ALLOWED_NETWORKS` explicitly. Individual IPv4 administrator devices
can use `/32`; individual IPv6 devices can use `/128`. The application also
automatically includes global IPv6 on-link networks detected in
`/host-proc/net/if_inet6`. **The environment variable alone does not exclude
those detected IPv6 networks.** Use host/network firewall rules if access must
be limited to particular administrator devices on IPv6.

The action uses a short-lived, client-bound token and same-origin requests.
AdGuard credentials remain on the server. Before changing custom rules, it:

- Checks local process/host/cgroup memory headroom twice.
- Serializes updates and backs up the previous custom-rule list.
- Persists pending state before sending a write, then checks A and AAAA results.
- Applies a cooldown and never automatically repeats an uncertain write.

AdGuard rebuilds its filtering engines when custom rules change. The memory
check reduces risk but cannot guarantee that a rebuild will fit in RAM. Missing
memory data, multiple AdGuard processes, or insufficient headroom declines the
operation. Do not remove the read-only `/proc` and cgroup mounts, host cgroup
namespace, or persistent state volume to work around a declined operation.

After a successful change, clients can retain their earlier DNS answer; wait
and refresh if the page persists. An unconfirmed change remains pending across
restarts. Check AdGuard's actual rules and logs before recovery; deleting the
state to force a retry can duplicate an uncertain mutation.

## Updates and removal

For a source-built Compose deployment, replace the source with the intended
release and run `docker compose up -d --build` again. Keep `.env` and the
`unblock_state` volume. For Portainer, use the stack file supplied with the new
release and retain the existing environment values and state volume.

When updating from the earlier deployment examples, explicitly set
`UNBLOCK_ALLOWED_NETWORKS` and, for Portainer, `AGH_CONTAINER` and
`AGH_DNS_SERVER`. These values are no longer selected for a particular home
network by the deployment files.

To stop/remove only this Compose service:

```sh
docker compose down
```

This retains the state volume and does not remove AdGuard allowlist rules.
Before permanently removing the service, change AdGuard's Custom IP blocking
setting so blocked DNS answers no longer point at a stopped web server.

## Frequently asked questions

### How do I add a custom block page to AdGuard Home?

Run the service on an available port 80, then set AdGuard's **Custom IP**
blocking responses to the block-page host's reachable IPv4/IPv6 addresses.
Clients must use that AdGuard instance for DNS. Start with
[Docker Compose](#quick-start-with-docker-compose) or
[Portainer](#portainer-installation), then [configure AdGuard](#configure-adguard-home).

### Why does a blocked HTTPS website show an error instead of the page?

This service does not intercept TLS. HTTPS-only sites, HSTS, and HTTPS-first
browser behavior can prevent an HTTP replacement page from appearing. Test
with an explicit `http://` URL; see [requirements and limits](#requirements-and-limits).

### Do I need an ASUS router, and which setups are supported?

No particular router brand is required. The documented setup uses Linux Docker
Engine with modern Docker Compose, or Portainer on Docker Standalone, with
IPv6 socket support. The Unblock action additionally requires AdGuard on the
same host; see the [deployment requirements](#requirements-and-limits).

### Does Unblock allow a website for only my device?

It allows the hostname and its subdomains for **all clients** using AdGuard.
Authorization also includes detected global IPv6 on-link networks, which
`UNBLOCK_ALLOWED_NETWORKS` alone does not exclude. Review
[Unblock permissions](#unblock-permissions-and-persistence) before enabling access.

### Why is Unblock declined or still pending?

Insufficient verified memory headroom, unavailable host data, a cooldown, or an
earlier unconfirmed write can prevent another update. The app does not
automatically repeat uncertain writes or restart AdGuard. See
[persistence and recovery](#unblock-permissions-and-persistence) and
[troubleshooting](#troubleshooting).

### Does the page list every blocklist containing the domain?

It shows AdGuard's applied rules, matching custom rules, and available local
query-log evidence. It does not scan every subscribed list. See
[rule-reporting limits](#requirements-and-limits).

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Stack validation fails | Fill every required environment value; update Compose/Portainer if `cgroup` is unsupported. |
| Portainer reports a missing container | Set `AGH_CONTAINER` to the actual existing AdGuard container name. |
| Downloads keep retrying | Check the configured DNS servers and access to `raw.githubusercontent.com`; inspect the container log. |
| Port 80 is occupied | Inspect the host's listeners; another web server cannot use the same address/port. |
| Status works but blocked pages do not | Check AdGuard blocking mode, both A/AAAA responses, client DNS selection, and HTTPS behavior. |
| Missing device/rule details | Check API URL/credentials and optional file mounts. MAC/neighbor information is not always available. |
| Unblock is declined | Check authorization, same-host API address, host mounts, readable process/cgroup data, available RAM, and pending state. |

## Support

[Open a GitHub issue](https://github.com/Eabusham2/adguard-home-blockpage/issues)
with the selected release, application version, Linux/Docker/Compose or
Portainer versions, deployment file used, and steps to reproduce the problem.
Include relevant redacted logs, whether the URL uses HTTP or HTTPS, and whether
`/healthz` works. A healthy listener alone does not verify AdGuard credentials
or DNS filtering. Remove passwords, client addresses/names, and private browsing
data before sharing logs or configuration.

## Development and releases

The application uses Python's standard library. Contributor and coding-agent
guidance is in [AGENTS.md](AGENTS.md), including the module map, isolated checks,
and immutable Portainer source-pin rules. Run the same non-destructive checks
as CI with Python 3.13:

```sh
python scripts/validate.py
```

CI also validates both Compose files, including a second set of network values,
verifies that the Portainer source pin matches all four release modules, and
builds and smoke-tests the Docker image.
Release tags use `vMAJOR.MINOR.PATCH` and must match `APP_VERSION` in `app.py`.
The release workflow runs validation first, then publishes a source tarball and
`SHA256SUMS`. Manual dispatch requires an existing release tag and its full
commit SHA; it rejects a mismatch.

To verify a downloaded bundle on Linux, put it beside `SHA256SUMS` and run
`sha256sum -c SHA256SUMS` (on macOS: `shasum -a 256 -c SHA256SUMS`).

## Related projects

[AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) is the DNS filtering
service this block page connects to. These other router projects are
independent and are **not required** to run the block page:

| Project | Purpose |
| --- | --- |
| [Router VPN](https://github.com/Eabusham2/router-vpn) | Self-hosted VPN/proxy platform with native clients; consult its current release and platform status. |
| [FlowCache Doctor](https://github.com/Eabusham2/asuswrt-merlin-flowcache-doctor) | Router diagnostics and targeted FlowCache recovery for the documented ASUS GT-BE19000AI / Asuswrt-Merlin setup. |
| [Asuswrt DynBQ v3](https://github.com/Eabusham2/asuswrt-dynbq-v3) | Experimental, firmware-specific Broadcom queue-control source for developers and validated installations. |

## License

[MIT](LICENSE).

## Search keywords (ignore)

`adguard`, `adguard-home`, `adguard-home-blockpage`, `block-page`, `blockpage`, `custom-block-page`,
`custom-blockpage`, `blocked`, `blocked-website`, `dns`, `dns-filtering`, `dns-block-page`,
`http`, `http-block-page`, `https-limitations`, `custom-ip`, `ipv4`, `ipv6`,
`dual-stack`, `docker`, `docker-compose`, `portainer`, `docker-standalone`, `linux`,
`self-hosted`, `homelab`, `networking`, `dark-mode`, `allowlist`, `domain-exceptions`,
`blocked-services`, `dns-rewrites`, `query-log`, `device-details`, `lan-authorization`, `memory-preflight`,
`cname`, `filter-rules`, `client-names`, `unblock-button`, `responsive-design`
