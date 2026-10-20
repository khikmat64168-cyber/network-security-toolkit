# Deploying NST to the VPS

```
                     ┌──────────── Caddy (HTTPS, ports 80/443) ───────────┐
PUBLIC_HOST       →  │  /       → Networkscan-front (static files)       │
                     │  /api/*  → nst-public   127.0.0.1:8766            │  TLS + GeoIP only, no capture,
                     │                                                   │  rate-limited, SSRF-guarded
CONSOLE_HOST      →  │  basic auth, then token                           │
                     │  /       → Networkscan-front                      │
                     │  /api/*  → nst-console  127.0.0.1:8765            │  full console, captures the
                     └───────────────────────────────────────────────────┘  VPS's own traffic
```

Both backends listen on loopback only; Caddy is the only thing reachable
from the internet. Releases are driven by git tags in the two repositories:

| Repo | Tag `vX.Y.Z` does |
|---|---|
| network-security-toolkit | tests → image to GHCR → wheel on GitHub Releases → `deploy.sh` on the VPS |
| Networkscan-front | tests → `dist` archive on GitHub Releases → `deploy-front.sh` on the VPS |

## 1. One-time: SSH key for GitHub Actions

On your computer:

```bash
ssh-keygen -t ed25519 -N "" -C "github-actions-deploy" -f ~/.ssh/nst_deploy
```

`~/.ssh/nst_deploy.pub` goes to the VPS (next step); `~/.ssh/nst_deploy`
(private) goes to GitHub secrets (step 3).

## 2. One-time: prepare the VPS

Copy the setup script and run it as root (Ubuntu 22.04 / 24.04):

```bash
scp deploy/vps-setup.sh root@VPS_IP:/root/
```

```bash
ssh -t root@VPS_IP "bash /root/vps-setup.sh --email you@example.com --ci-key '$(cat ~/.ssh/nst_deploy.pub)'"
```

It installs Docker, creates the `deploy` user, opens only SSH/80/443,
writes `/opt/nst/deploy/.env` (host names default to `<ip>.sslip.io` and
`console.<ip>.sslip.io`, plus a random console token) and asks for the
console's basic-auth password (that is why `ssh -t` is needed).

## 3. One-time: GitHub secrets (both repositories)

Settings → Secrets and variables → Actions → *New repository secret*:

| Secret | Value |
|---|---|
| `VPS_HOST` | the VPS IP |
| `VPS_SSH_KEY` | contents of `~/.ssh/nst_deploy` |
| `VPS_KNOWN_HOSTS` | output of `ssh-keyscan -t ed25519 VPS_IP` |

Settings → Environments → create **production** (optionally require your
approval before each deploy).

## 4. First releases (order matters once)

1. **Backend first** — it installs `deploy-front.sh` on the VPS:

   ```bash
   git tag v1.0.0 && git push origin v1.0.0
   ```

2. **Frontend** (in Networkscan-front):

   ```bash
   git tag v1.0.0 && git push origin v1.0.0
   ```

   The backend's *wheel* job bundles the frontend release pinned in
   `frontend.version`; if it ran before the frontend release existed,
   re-run that job from the Actions tab.

Then open `https://<ip>.sslip.io` (public demo) and
`https://console.<ip>.sslip.io` (basic auth, then the token from
`sudo grep NST_WEB_TOKEN /opt/nst/deploy/.env` on the VPS).

## Switching to a real domain later

1. DNS: A records `example.com` and `console.example.com` → VPS IP.
2. On the VPS, edit `/opt/nst/deploy/.env`: `NST_PUBLIC_HOST=example.com`,
   `NST_CONSOLE_HOST=console.example.com`.
3. Apply:

   ```bash
   ssh deploy@VPS_IP "cd /opt/nst/deploy && docker compose up -d"
   ```

Caddy obtains the new certificates by itself. Nothing in the code changes.

## Operating

```bash
# status and logs
ssh deploy@VPS_IP "cd /opt/nst/deploy && docker compose ps && docker compose logs --tail 50"
```

```bash
# roll back to an earlier release
ssh deploy@VPS_IP "/opt/nst/deploy/deploy.sh v1.0.0"
```

`deploy.sh` waits for both backends to answer and rolls back by itself if
a new release does not come up. Frontend releases are kept under
`/srv/networkscan-front/releases/` (newest five); re-running a frontend
release's deploy job switches back to it.

Capture in the console sees only the VPS's own network interface — ARP and
MAC detection are of little use in a data-centre network; traffic, DNS,
TLS and GeoIP are.
