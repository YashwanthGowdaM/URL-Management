# URL Registry

Public, read-only list of links at https://url.yashwanthgowdam.in. Adding, editing and deleting
requires sign-in with password **and** a TOTP code (any authenticator app).

Stack: Node 22 / Express, SQLite (WAL), vanilla JS front end, Caddy (automatic HTTPS), Docker Compose.

## Security notes
- Passwords: scrypt (N=2^15). TOTP: RFC 6238 with replay protection; first login enrols the authenticator.
- Sessions: random 256-bit token, stored hashed server-side; `__Host-` cookie, HttpOnly, Secure, SameSite=Strict, 8h.
- CSRF: per-session token required on every write. Login and code endpoints are rate-limited; 5 code attempts per sign-in.
- All SQL is parameterised; the UI never uses innerHTML; strict CSP (no inline script/style); only http(s) URLs accepted.
- Container: non-root, read-only filesystem, all capabilities dropped. Only Caddy publishes ports.

## One-time setup
1. Locally: `npm install` and commit `package-lock.json` (CI uses `npm ci`). Run `npm test`.
2. DNS: A record `url.yashwanthgowdam.in` -> VM public IP. Open ports 80/443.
3. VM: install Docker + Compose plugin, then
   `sudo mkdir -p /opt/url-registry && sudo chown $USER /opt/url-registry`
   and create `/opt/url-registry/.env` from `.env.example` (`chmod 600`; set a 12+ char `ADMIN_PASSWORD`).
4. VM: add a GitHub self-hosted runner (Settings > Actions > Runners) with the label `url-registry`,
   run as a user in the `docker` group. Use a **private** repo for self-hosted runners.
5. GitHub: create an environment named `production` (optionally require approval).
6. Package visibility: GHCR images are private by default; the deploy job logs in with `GITHUB_TOKEN`
   for the pull, so no extra secrets are needed.
7. Push to `main`. First sign-in: scan the QR code, enter the code, then remove `ADMIN_PASSWORD` from `.env`.

## Operations
- Backup: `docker run --rm -v url-registry_registry-data:/data -v $PWD:/out alpine tar czf /out/registry.tgz /data`
- Lost authenticator: `docker compose exec app node -e "import('./src/db.js').then(({db})=>db.prepare('UPDATE users SET totp_secret=NULL').run())"`
  then sign in again to re-enrol.
- Local dev: `ADMIN_USER=admin ADMIN_PASSWORD=change-me-please npm start` (http://localhost:3000).
