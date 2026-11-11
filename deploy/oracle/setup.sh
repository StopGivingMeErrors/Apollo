#!/usr/bin/env bash
# Run on a fresh Oracle Always Free Ubuntu VM as a user with sudo.
set -euo pipefail

VERCEL_ORIGIN="${VERCEL_ORIGIN:-https://sentinel-soc-sand.vercel.app}"
REPO_DIR="${REPO_DIR:-$HOME/sentinel}"

if [[ $EUID -eq 0 ]]; then
  echo "Run as ubuntu (or another sudoer), not as root."
  exit 1
fi

echo "==> Installing Docker"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
fi
sudo apt-get update -y
sudo apt-get install -y docker-compose-plugin iptables-persistent curl openssl

echo "==> Opening OS firewall (Oracle Ubuntu images REJECT inbound by default)"
# Insert BEFORE the catch-all REJECT so host-bound and edge cases work.
# Docker-published ports usually traverse FORWARD, but INPUT rules are cheap insurance.
for port in 80 443 22 2222 8080 2121 2323; do
  sudo iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null \
    || sudo iptables -I INPUT 5 -p tcp --dport "$port" -j ACCEPT
done
sudo netfilter-persistent save || sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null

PUBLIC_IP="$(curl -fsS https://ifconfig.me/ip || curl -fsSL https://api.ipify.org)"
DOMAIN="${PUBLIC_IP}.sslip.io"
echo "==> Public hostname: https://${DOMAIN}"

mkdir -p "$REPO_DIR"
if [[ ! -f "$REPO_DIR/.env" ]]; then
  KEY="$(openssl rand -hex 24)"
  cat > "$REPO_DIR/.env" <<EOF
SENTINEL_API_KEY=${KEY}
SENTINEL_ORIGINS=${VERCEL_ORIGIN}
SENTINEL_LIVE_ATTACKS=0
SENTINEL_SEED_ON_EMPTY=0
SENTINEL_PUBLIC_DOCS=0
SENTINEL_DOMAIN=https://${DOMAIN}
EOF
  echo "==> Wrote $REPO_DIR/.env (API key generated)"
fi

cat > "$REPO_DIR/Caddyfile" <<EOF
${DOMAIN} {
  encode gzip
  reverse_proxy api:8000 {
    flush_interval -1
  }
}
EOF

echo "==> Starting API + Caddy"
cd "$REPO_DIR"
if docker info >/dev/null 2>&1; then
  COMPOSE="docker compose"
else
  COMPOSE="sudo docker compose"
fi
$COMPOSE -f docker-compose.oracle.yml up -d --build

echo
echo "Wait ~40s for first boot (image pull + seed), then:"
echo "  curl -fsS https://${DOMAIN}/api/health"
echo
echo "API key is in $REPO_DIR/.env"
echo "If docker permission denied, log out and back in once."
