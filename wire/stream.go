package wire

import (
	"context"
	"fmt"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	xgrpc "github.com/xtls/xray-core/transport/internet/grpc"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

// buildStream turns a PathSpec into Xray transport settings. Only the
// transports this core supports are mapped; anything else is an error so the
// catalogue loader can skip the path explicitly.
func buildStream(s PathSpec) (*internet.MemoryStreamConfig, error) {
	sc := &internet.StreamConfig{}
	switch s.Network {
	case "tcp":
		sc.ProtocolName = "tcp"
		sc.TransportSettings = []*internet.TransportConfig{{ProtocolName: "tcp", Settings: serial.ToTypedMessage(&tcp.Config{})}}
	case "ws":
		sc.ProtocolName = "websocket"
		sc.TransportSettings = []*internet.TransportConfig{{ProtocolName: "websocket", Settings: serial.ToTypedMessage(&websocket.Config{Host: s.HostHeader, Path: s.Path})}}
	case "grpc":
		// mode=gun (default) is one stream per flow; mode=multi packs frames.
		sc.ProtocolName = "grpc"
		sc.TransportSettings = []*internet.TransportConfig{{ProtocolName: "grpc", Settings: serial.ToTypedMessage(&xgrpc.Config{Authority: s.Authority, ServiceName: s.ServiceName, MultiMode: s.Mode == "multi"})}}
	case "xhttp":
		sc.ProtocolName = "splithttp"
		sc.TransportSettings = []*internet.TransportConfig{{ProtocolName: "splithttp", Settings: serial.ToTypedMessage(&splithttp.Config{Host: s.HostHeader, Path: s.Path, Mode: s.Mode})}}
	default:
		return nil, fmt.Errorf("transport %q is not supported", s.Network)
	}
	fp := s.Fingerprint
	if fp == "" {
		fp = "chrome"
	}
	switch s.Security {
	case "reality":
		cfg := &reality.Config{
			ServerName:  s.SNI,
			Fingerprint: fp,
			PublicKey:   s.PublicKey,
			ShortId:     s.ShortID,
			SpiderX:     s.SpiderX,
		}
		sc.SecurityType = serial.GetMessageType(cfg)
		sc.SecuritySettings = []*serial.TypedMessage{serial.ToTypedMessage(cfg)}
	case "tls":
		alpn := s.ALPN
		if len(alpn) == 0 && s.Network == "ws" {
			alpn = []string{"http/1.1"}
		}
		cfg := &tls.Config{
			ServerName:    s.ServerSNI(),
			Fingerprint:   fp,
			NextProtocol:  alpn,
			AllowInsecure: s.Insecure,
		}
		sc.SecurityType = serial.GetMessageType(cfg)
		sc.SecuritySettings = []*serial.TypedMessage{serial.ToTypedMessage(cfg)}
	case "none", "":
	default:
		return nil, fmt.Errorf("security %q is not supported", s.Security)
	}
	return internet.ToMemoryStreamConfig(sc)
}

// dialStream establishes the outer transport of a Trojan or VMess path (TCP +
// TLS/REALITY, the WebSocket upgrade, the gRPC stream or the XHTTP session).
func dialStream(ctx context.Context, name string, dest xnet.Destination, mss *internet.MemoryStreamConfig) (stat.Connection, error) {
	return internet.Dial(session.ContextWithOutbounds(ctx, []*session.Outbound{{Name: name}}), dest, mss)
}
