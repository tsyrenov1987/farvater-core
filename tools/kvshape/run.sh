#!/bin/bash
# run.sh <серия>: по одному прогону каждого вида, дамп на узле на каждый прогон. Стенд: копия фронта nginx на портах
# 18471 (kilvaterd -pad moderate) и 18472 (-pad site), страницы get-*/post-* и peers.py на узле; wire.test = go test -c ./wire.
# Разбор: rec.py <pcap> <адрес узла> > x.json на каждый дамп, затем stats.py <каталог json>.
N=${KVSHAPE_NODE:?root@узел}; ME=${KVSHAPE_CLIENT_IP:?адрес клиента, каким его видит узел}; HOST=${KVSHAPE_HOST:?имя стенда}; SSH="ssh -o ControlMaster=auto -o ControlPath=/tmp/kvlab-%r@%h -o ControlPersist=120"
L=$(dirname "$0"); KEY=$($SSH $N "grep -v '^#' /root/kvlab/keys.txt | head -1")
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
cap() { # cap <метка> <команда...>
  local lab=$1; shift
  $SSH $N "nohup tcpdump -i ens18 -w /root/kvlab/pcap/$lab.pcap 'host $ME and (tcp port 18471 or tcp port 18472)' >/dev/null 2>&1 & echo \$! > /root/kvlab/td.pid; sleep 0.7"
  "$@" > "$L/out-$lab.txt" 2>&1; echo "$lab: $(grep -E 'down |up |done|title|FAIL|ended' "$L/out-$lab.txt" | head -2 | tr '\n' ' ' | cut -c1-150)"
  sleep 1; $SSH $N 'kill $(cat /root/kvlab/td.pid); sleep 0.3'
}
chrome() { rm -rf "$L/chr"; perl -e 'alarm 90; exec @ARGV' "$CHROME" --headless=new --disable-gpu --no-first-run --disable-background-networking --user-data-dir="$L/chr" --dump-dom "$1" 2>/dev/null | grep -o '<title>[^<]*'; }
tun() { KILLIVE_URI="kilvater://$KEY@$HOST:$1?sni=$HOST&pad=$2" KILLIVE_TARGET=127.0.0.1:$3 KILLIVE_UP=$4 "$L/wire.test" -test.run TestKilvaterLiveLab -test.v -test.count=1; }
r=$1
cap chrome-get8-$r   chrome "https://$HOST:18471/get-big.bin.html"
cap chrome-get1-$r   chrome "https://$HOST:18471/get-promo.mp4.html"
cap chrome-post8-$r  chrome "https://$HOST:18471/post-8388608.html"
cap chrome-post1-$r  chrome "https://$HOST:18471/post-1166826.html"
for m in moderate:18471 site:18472; do pad=${m%%:*}; port=${m#*:}
  cap tun-$pad-down8-$r tun $port $pad 19080 0
  cap tun-$pad-down1-$r tun $port $pad 19082 0
  cap tun-$pad-up8-$r   tun $port $pad 19081 8388608
  cap tun-$pad-up1-$r   tun $port $pad 19081 1166826
done
