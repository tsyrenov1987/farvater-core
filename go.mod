module github.com/tsyrenov1987/farvater-core

go 1.26.0

// Clean-room stand-in for the one sing package xray links (see NOTICE).
// Use `go mod tidy -e`: tidy also loads tests of dependencies, and those
// import sing packages the shim deliberately does not provide.
replace github.com/sagernet/sing => ./third_party/sing-shim

require (
	github.com/apernet/hysteria/core/v2 v2.13.0
	github.com/apernet/hysteria/extras/v2 v2.13.0
	github.com/refraction-networking/utls v1.8.3-0.20260301010127-aa6edf4b11af
	github.com/xtls/xray-core v1.260327.0
	golang.org/x/mobile v0.0.0-20260908204917-8b95e45f8d3e
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/pires/go-proxyproto v0.11.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/sagernet/sing v0.5.1 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/xtls/reality v0.0.0-20260322125925-9234c772ba8f // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
)
