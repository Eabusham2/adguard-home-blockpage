# AdGuard Home Block Page

A small HTTP block page for AdGuard Home, designed for Docker/Portainer and dual-stack home networks.

## Features

- IPv4 and IPv6 HTTP listener
- Real client address with Docker host networking
- Resolves the AdGuard client/device name from persistent clients, client search, query-log metadata, or reverse DNS when available
- Shows associated IPv4 and IPv6 addresses; host-network ARP/NDP data can link a temporary IPv6 address back to the same LAN device
- Shows the LAN MAC address only when it can be determined from AdGuard client IDs or the host neighbor table
- Checks both A and AAAA filtering results
- Shows every distinct **applied** rule/list returned by AdGuard Home and labels common rule forms (Domain, Wildcard, Regex, Hosts, DNS rewrite, CNAME rewrite, Adblock)
- Shows blocked-service, CNAME, and rewrite-address data when AdGuard returns them
- Automatic light/dark mode
- Plain responsive system-style UI with no JavaScript, gradients, or decorative branding
- Direct IP visits show a service-status page

## Important limitation about multiple blocklists

AdGuard Home's `filtering/check_host` API reports the rules it actually applies. A hostname can exist in several subscribed lists while AdGuard returns only the applied rule(s). This project displays every rule/list AdGuard reports for both A and AAAA; it does not independently download and scan every blocklist.

## Portainer

Use `network_mode: host` so the web server receives the real LAN client address instead of a Docker bridge/proxy address.

Required environment variables:

```env
AGH_URL=http://192.168.1.2:3000
AGH_USERNAME=your_username
AGH_PASSWORD=your_password
```

Never commit real AdGuard Home credentials to a public repository.

## AdGuard Home

Set DNS blocking mode to **Custom IP** and point blocked A/AAAA responses at the machine running this service. Port 80 must be reachable on that address.

## HTTPS

This is an HTTP block page. A transparent custom page for arbitrary HTTPS sites requires clients to trust an interception certificate; without that, HTTPS blocks normally fail certificate validation before an HTTP replacement page can be shown.

## License

MIT
