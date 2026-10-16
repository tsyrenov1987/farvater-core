#!/bin/sh
# sleep.sh for an iPhone: polls the chaos lab app's tmp/chaos-sleep over
# devicectl, stops the process it names for the seconds it asks and lets it
# run again. The scenario removes the file when it wakes; the driver waits for
# that before it takes another.
DEV=${1:?device id}
APP=${2:-app.farvater.chaoslab}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fetch() {
  rm -f "$TMP/f"
  xcrun devicectl device copy from -q --device "$DEV" --domain-type appDataContainer \
    --domain-identifier "$APP" --source tmp/chaos-sleep --destination "$TMP/f" >/dev/null 2>&1 && [ -s "$TMP/f" ]
}
sig() { xcrun devicectl device process signal -q --device "$DEV" --pid "$1" --signal "$2" >/dev/null 2>&1; }
while :; do
  if fetch && read -r pid secs < "$TMP/f"; then
    echo "sleep-device.sh: stop $pid for ${secs}s"
    sig "$pid" SIGSTOP && sleep "$secs"
    sig "$pid" SIGCONT
    echo "sleep-device.sh: woke $pid"
    while fetch; do sleep 1; done
  fi
  sleep 0.5
done
