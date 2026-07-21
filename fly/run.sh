#!/bin/bash
# Container entrypoint. --internal on the volume is what makes accounts and
# sessions survive restarts; --plugins-dir loads the three sample providers
# (flat copies, so no loader shim is needed — Datasette registers every .py).
# profile_access for any signed-in actor mirrors `just dev` in the plugin repo.
# Fly terminates TLS, so the app perceives http: force_https_urls keeps
# generated URLs + the CSRF origin-fallback on https, and trust_proxy_headers
# makes the plugin read X-Forwarded-For/-Proto (real client IPs for the
# login-attempt audit, lockouts, and secure cookies).
# --default-deny drops core's default view-* allows: databases are invisible
# until granted (admins manage this via datasette-acl). view-instance stays
# open to everyone (allow block `true` matches anonymous) so the homepage and
# sign-in surface work.
uv run datasette --internal /mnt/internal.db /mnt/data.db \
  /mnt/congress-legislators.db \
  --create \
  --default-deny \
  --plugins-dir plugins \
  -s permissions.view-instance true \
  -s permissions.profile_access.id '*' \
  -s force_https_urls 1 \
  -s plugins.datasette-accounts.trust_proxy_headers 1 \
  -h 0.0.0.0 -p "${PORT:-8080}"
