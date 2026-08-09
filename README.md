# AdGuard Home Block Page

A lightweight, responsive HTTP block page for **AdGuard Home**, built for Docker/Portainer.

## Features

- IPv4 + IPv6 listener
- Real LAN client IP with host networking
- AdGuard client/device name when available
- Automatic light/dark mode; responsive on phones, tablets, and desktops
- Friendly reason plus AdGuard's technical reason code
- Every applied rule returned by AdGuard Home for both **A and AAAA** checks
- Filter-list names from `filter_list_id`
- Blocked-service name when present
- **CNAME rewrite** and rewrite IP addresses when AdGuard returns them
- Direct-IP status page and `/healthz`

## Important limits

This is DNS + HTTP. It cannot transparently replace arbitrary **HTTPS** sites without a trusted interception certificate on client devices.

AdGuard Home's `/control/filtering/check_host` API returns **applied rules** as an array. This project displays every rule/list AdGuard returns for A and AAAA. If a domain exists in several subscribed lists but AdGuard only reports one winning/applied rule, the page cannot truthfully infer the others.

AdGuard documents `cname` and `ip_addrs` on this endpoint for DNS rewrites. A normal upstream CNAME chain may not exist when a domain is blocked before upstream resolution.

## Portainer

1. Download `portainer-stack.yml`.
2. Portainer -> **Stacks -> Add stack -> Upload**.
3. Upload it.
4. Under **Environment variables -> Advanced mode** paste:

```env
AGH_URL=http://YOUR-ADGUARD-IP:3000
AGH_USERNAME=YOUR_USERNAME
AGH_PASSWORD=YOUR_PASSWORD
```

5. Deploy.

The Docker host must have TCP port 80 available.

## AdGuard Home

Set **Settings -> DNS settings -> Blocking mode -> Custom IP**, and point blocked IPv4/IPv6 answers at this Docker host.

## Why did I see `172.18.0.1`?

That is typically the gateway address of a Docker bridge network, not the real client. Depending on the published-port/NAT path, the application can see the Docker-side gateway instead of the LAN device. This project uses `network_mode: host` on Linux to remove that bridge/NAT layer so the HTTP server can see the real peer IP.

## Security

Never commit real AdGuard credentials. Keep them in Portainer environment variables or an uncommitted local `.env` file.

## License

MIT
