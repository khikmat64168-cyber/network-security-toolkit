# Deploying NST to the VPS (Coolify)

How this deployment was built, step by step, with the problems hit along
the way (in Uzbek): [DEPLOY_JARAYONI.md](DEPLOY_JARAYONI.md).

The VPS already runs **Coolify**, whose Traefik proxy owns ports 80/443 and
serves the other apps. NST fits into that instead of bringing its own proxy:

```
Internet ──► Traefik (Coolify, HTTPS) ──► nst-public container :8766
                                           public demo: TLS + GeoIP, web console UI,
                                           no capture, no token, rate-limited, SSRF-guarded

You ──SSH tunnel──► 127.0.0.1:8765 on the VPS ──► nst-console container (host network)
                                           full console: sensors capture the VPS's traffic,
                                           never reachable from the internet
```

Nothing here touches Coolify's own containers, Docker's installation or the
firewall.

| Release | What happens |
|---|---|
| Networkscan-front tag `vX.Y.Z` | `dist` archive published on GitHub Releases |
| network-security-toolkit tag `vX.Y.Z` | tests → image (with the console from `frontend.version`) on GHCR → wheel on GitHub Releases → Coolify redeploys the public demo → the private console is updated over SSH |

To ship a new console: release Networkscan-front, bump `frontend.version`
here, release the backend.

## 1. One-time: the private console's host user

The SSH key GitHub Actions uses (public half in `~/.ssh/nst_deploy.pub`):

```bash
ssh-keygen -t ed25519 -N "" -C "github-actions-deploy" -f ~/.ssh/nst_deploy
```

Create the `deploy` user and `/opt/nst-console` (no packages, no firewall
changes):

```bash
scp deploy/console-setup.sh root@VPS:/root/
```

```bash
ssh root@VPS "bash /root/console-setup.sh --ci-key '$(cat ~/.ssh/nst_deploy.pub)'"
```

## 2. First releases

1. Networkscan-front: `git tag v1.0.0 && git push origin v1.0.0`
2. This repo: `git tag v1.0.0 && git push origin v1.0.0`

The *image* job publishes `ghcr.io/khikmat64168-cyber/network-security-toolkit`.
The two deploy jobs fail on this first run until steps 3–4 are done; that
is expected.

## 3. One-time: make the image public

GitHub → your profile → **Packages** → `network-security-toolkit` →
**Package settings** → *Change visibility* → **Public**. (The source is
public anyway; this lets Coolify and the VPS pull without credentials.)

## 4. One-time: the public demo in Coolify

1. Coolify → a project → **+ New** → **Docker Image** →
   `ghcr.io/khikmat64168-cyber/network-security-toolkit:latest`.
2. **Domains**: `https://nst.<ip-with-dashes>.sslip.io` for now, or a real
   name (e.g. `https://nst.example.com` after an A record points to the VPS).
3. **Ports exposes**: `8766`.
4. **Environment variables**: `NST_ALLOWED_HOSTS` = the domain's host name
   (without `https://`).
5. **Health check**: path `/api/mode`, port `8766`.
6. Deploy, then note the resource's **Deploy Webhook** URL and create an API
   token under **Keys & Tokens** (deploy permission).

## 5. One-time: GitHub settings (this repo)

Settings → Secrets and variables → Actions:

| Secret | Value |
|---|---|
| `COOLIFY_DEPLOY_WEBHOOK` | the Deploy Webhook URL from step 4 |
| `COOLIFY_API_TOKEN` | the Coolify API token |
| `VPS_HOST` | VPS IP |
| `VPS_SSH_KEY` | contents of `~/.ssh/nst_deploy` |
| `VPS_KNOWN_HOSTS` | output of `ssh-keyscan -t ed25519 VPS` |

Variables tab: `PUBLIC_URL` = the demo's URL (e.g. `https://nst.example.com`).
Settings → Environments → create **production**.

Then re-run the failed deploy jobs of the v1.0.0 release (Actions → the run
→ *Re-run failed jobs*). Later releases deploy on their own.

## Using the private console

```bash
ssh -L 8765:127.0.0.1:8765 deploy@VPS
```

Open `http://127.0.0.1:8765/` and paste the token from:

```bash
ssh root@VPS "grep NST_WEB_TOKEN /opt/nst-console/.env"
```

The console sees only the VPS's own traffic: traffic, DNS, TLS and GeoIP
are useful there; ARP and MAC detection are of little use in a data-centre
network.

## Operating

```bash
# console status / logs / roll back
ssh deploy@VPS "cd /opt/nst-console && docker compose ps && docker compose logs --tail 50"
```

```bash
ssh deploy@VPS "/opt/nst-console/deploy-console.sh v1.0.0"
```

The public demo's logs, restarts and rollbacks are in Coolify's UI for the
resource.
