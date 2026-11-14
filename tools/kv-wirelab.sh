#!/bin/sh
# What does a kilvater tunnel look like on the wire next to the decoy site?
#
# Puts kilvaterd (-h2c) behind a local nginx that ends TLS and serves a static
# file, the way production nodes are set up, then compares the lengths of the
# TLS records of (a) a download of that file and (b) the same amount of data
# through the tunnel, for each padding mode. Prints, per mode, the record
# length distribution and its distance to the static download; the lines
# "another static download" show how far the reference is from itself.
#
# Loopback only: it shows record sizes, not timing, and not what a real
# network path does to them. Needs nginx (with http_v2 and http_ssl) and
# openssl. Usage: tools/kv-wirelab.sh [mode ...]   (default: off moderate heavy site)
set -eu
cd "$(dirname "$0")/.."
L=$(mktemp -d)
trap 'nginx -c "$L/nginx.conf" -s quit 2>/dev/null || true; [ -n "${KV:-}" ] && kill "$KV" 2>/dev/null || true; rm -rf "$L"' EXIT
mkdir -p "$L/www" "$L/logs"
go build -o "$L/kilvaterd" ./cmd/kilvaterd
"$L/kilvaterd" -genkey > "$L/keys.txt"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$L/key.pem" \
  -out "$L/cert.pem" -days 2 -subj "/CN=lab.test" -addext "subjectAltName=DNS:lab.test" 2>/dev/null
head -c 8388608 /dev/urandom > "$L/www/big.bin"
echo "<html>lab</html>" > "$L/www/index.html"
cat > "$L/nginx.conf" <<CONF
worker_processes 1;
pid $L/nginx.pid;
error_log $L/logs/error.log crit;
events { worker_connections 256; }
http {
  access_log off;
  client_body_temp_path $L/logs/cb; proxy_temp_path $L/logs/pt; fastcgi_temp_path $L/logs/fc;
  uwsgi_temp_path $L/logs/uw; scgi_temp_path $L/logs/sc;
  map "\$request_method:\$cookie__sid" \$kv_tunnel { default 0; "~^POST:.{43,55}\$" 1; }
  server {
    listen 127.0.0.1:8443 ssl;
    http2 on;
    ssl_certificate $L/cert.pem; ssl_certificate_key $L/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    root $L/www;
    client_max_body_size 0;
    location / {
      if (\$kv_tunnel) { grpc_pass grpc://127.0.0.1:28591; }
      grpc_read_timeout 1h; grpc_send_timeout 1h;
    }
  }
}
CONF
nginx -c "$L/nginx.conf"
KEY=$(grep -v '^#' "$L/keys.txt" | head -1)
for PAD in ${*:-off moderate heavy site}; do
  "$L/kilvaterd" -h2c -listen 127.0.0.1:28591 -keys "$L/keys.txt" -decoy "$L/www" -allow-private \
    -self-ports 18080,18081 -pad "$PAD" > "$L/logs/kv.log" 2>&1 &
  KV=$!
  sleep 1
  echo "=== pad=$PAD"
  KILLAB_ADDR=127.0.0.1:8443 KILLAB_KEY=$KEY KILLAB_PAD=$PAD \
    go test ./wire/ -run TestKilvaterWireLab -count=1 -v -timeout 120s 2>&1 |
    grep -E "kilvater_wirelab_test.go:[0-9]+: |^FAIL|^panic" | sed 's/^ *kilvater_wirelab_test.go:[0-9]*: //'
  kill "$KV"; wait "$KV" 2>/dev/null || true; KV=
done
