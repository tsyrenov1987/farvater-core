#!/bin/sh
# Builds the chaos bindings and runs every scenario on the iPhone given by its id.
# Needs the farvater-ios build prerequisites (Go, gomobile, Xcode, xcodegen);
# XCAUTH may carry xcodebuild's -authenticationKey* arguments.
set -e
DEV=${1:?device id}
HERE=$(cd "$(dirname "$0")" && pwd)
CORE=$(cd "$HERE/../.." && pwd)
GOMOBILE=${GOMOBILE:-"$HOME/go/bin-xmobile/gomobile"}
GO=$(cd "$CORE" && go env GOROOT)/bin/go
SHIM=$(mktemp -d)
trap 'rm -rf "$SHIM"' EXIT
cat > "$SHIM/go" <<SH
#!/bin/sh
if [ "\$1" = mod ] && [ "\$2" = tidy ]; then shift 2; exec "$GO" mod tidy -e "\$@"; fi
exec "$GO" "\$@"
SH
chmod +x "$SHIM/go"
export PATH="$SHIM:$(dirname "$GOMOBILE"):$(dirname "$GO"):$PATH"
(cd "$CORE" && nice -n 10 "$GOMOBILE" bind -tags chaos -target=ios/arm64 -iosversion 17.0 -trimpath \
  -o "$HERE/FarvaterChaos.xcframework" ./devtest/chaos)
cd "$HERE" && xcodegen generate -q
xcodebuild test -project ChaosLab.xcodeproj -scheme ChaosLab -destination "platform=iOS,id=$DEV" \
  -derivedDataPath "${DERIVED:-/tmp/chaoslab-dd}" -allowProvisioningUpdates $XCAUTH
