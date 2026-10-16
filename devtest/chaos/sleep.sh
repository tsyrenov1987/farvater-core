#!/bin/sh
# Plays the phone going to sleep for the sleep_wake scenario: waits for the
# scenario's chaos-sleep file (a glob: "$TMPDIR/chaos-sleep" on the Mac, the
# app's tmp in the simulator's data directory), then stops the process it
# names for the seconds it asks, as iOS suspends an app, and lets it run again.
PATTERN=${1:?glob of the chaos-sleep file}
while :; do
  for f in $PATTERN; do
    if [ -f "$f" ] && read -r pid secs < "$f"; then
      rm -f "$f"
      echo "sleep.sh: stop $pid for ${secs}s"
      kill -STOP "$pid" && sleep "$secs"
      kill -CONT "$pid"
      echo "sleep.sh: woke $pid"
    fi
  done
  sleep 0.2
done
