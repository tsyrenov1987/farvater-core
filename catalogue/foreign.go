package catalogue

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// foreign turns the subscription bodies of other clients into share links, one
// per line, for the plain-list parser: Clash/Mihomo YAML (proxies:), sing-box
// JSON (outbounds with server/server_port), Xray JSON (one config or an array of
// them, as Happ, v2rayN and Remnawave's XRAY_JSON serve) and SIP008. A server
// these wires cannot carry (Shadowsocks 2022 or with a plugin, h2, QUIC...) is left out; ok is false
// when the body is none of these formats.
func foreign(t string) (links string, ok bool) {
	var out []string
	switch {
	case strings.HasPrefix(t, "{") || strings.HasPrefix(t, "["):
		var v any
		if json.Unmarshal([]byte(t), &v) != nil {
			return "", false
		}
		docs, isList := v.([]any)
		if !isList {
			docs = []any{v}
		}
		for _, d := range docs {
			m, _ := d.(map[string]any)
			if m == nil {
				continue
			}
			if _, ok := m["paths"]; ok {
				return "", false // our own catalogue
			}
			if srv, has := m["servers"].([]any); has {
				ok = true // SIP008
				for _, x := range srv {
					v := obj(x)
					if l := ssLink(str(v["method"]), str(v["password"]), str(v["server"]), str(v["server_port"]), first(str(v["remarks"]), str(v["id"])), str(v["plugin"])); l != "" {
						out = append(out, l)
					}
				}
			}
			obs, has := m["outbounds"].([]any)
			if !has {
				continue
			}
			ok = true
			remarks := str(m["remarks"])
			for _, o := range obs {
				ob, _ := o.(map[string]any)
				if ob == nil {
					continue
				}
				var l string
				if _, xray := ob["protocol"]; xray {
					l = xrayLink(ob, remarks)
				} else {
					l = singLink(ob)
				}
				if l != "" {
					out = append(out, l)
				}
			}
		}
	case clashYAML(t):
		var doc struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if yaml.Unmarshal([]byte(t), &doc) != nil {
			return "", false
		}
		ok = true
		for _, p := range doc.Proxies {
			if l := clashLink(p); l != "" {
				out = append(out, l)
			}
		}
	}
	return strings.Join(out, "\n"), ok
}

// clashYAML: a top-level "proxies:" key, which no share link nor base64 has.
func clashYAML(t string) bool {
	for _, l := range strings.Split(t, "\n") {
		if strings.HasPrefix(strings.TrimRight(l, "\r "), "proxies:") {
			return true
		}
	}
	return false
}

func clashLink(p map[string]any) string {
	kind := strings.ToLower(str(p["type"]))
	q := url.Values{}
	name, host, port := str(p["name"]), str(p["server"]), str(p["port"])
	if kind == "hysteria2" || kind == "hy2" {
		set(q, "sni", str(p["sni"]))
		if yes(p["skip-cert-verify"]) {
			q.Set("insecure", "1")
		}
		set(q, "obfs", str(p["obfs"]))
		set(q, "obfs-password", str(p["obfs-password"]))
		return link("hysteria2", first(str(p["password"]), str(p["auth"])), host, port, q, name)
	}
	if kind == "ss" {
		return ssLink(str(p["cipher"]), str(p["password"]), host, port, name, str(p["plugin"]))
	}
	user := str(p["uuid"])
	switch kind {
	case "vless":
		set(q, "flow", str(p["flow"]))
	case "vmess":
		set(q, "encryption", str(p["cipher"]))
	case "trojan":
		user = str(p["password"])
	default:
		return ""
	}
	network := first(str(p["network"]), "tcp")
	q.Set("type", network)
	switch network {
	case "ws":
		o := obj(p["ws-opts"])
		set(q, "path", str(o["path"]))
		set(q, "host", header(o["headers"]))
	case "grpc":
		set(q, "serviceName", str(obj(p["grpc-opts"])["grpc-service-name"]))
	case "xhttp":
		o := obj(p["xhttp-opts"])
		set(q, "path", str(o["path"]))
		set(q, "host", str(o["host"]))
		set(q, "mode", str(o["mode"]))
	}
	set(q, "sni", first(str(p["servername"]), str(p["sni"])))
	set(q, "fp", str(p["client-fingerprint"]))
	set(q, "alpn", list(p["alpn"]))
	if yes(p["skip-cert-verify"]) {
		q.Set("allowInsecure", "1")
	}
	security := "none"
	if yes(p["tls"]) || kind == "trojan" {
		security = "tls"
	}
	if r := obj(p["reality-opts"]); r != nil {
		security = "reality"
		set(q, "pbk", str(r["public-key"]))
		set(q, "sid", str(r["short-id"]))
	}
	q.Set("security", security)
	return link(kind, user, host, port, q, name)
}

func singLink(o map[string]any) string {
	kind := strings.ToLower(str(o["type"]))
	q := url.Values{}
	name, host, port := str(o["tag"]), str(o["server"]), str(o["server_port"])
	tls := obj(o["tls"])
	if kind == "hysteria2" {
		set(q, "sni", str(tls["server_name"]))
		if yes(tls["insecure"]) {
			q.Set("insecure", "1")
		}
		if ob := obj(o["obfs"]); ob != nil {
			set(q, "obfs", str(ob["type"]))
			set(q, "obfs-password", str(ob["password"]))
		}
		return link("hysteria2", str(o["password"]), host, port, q, name)
	}
	if kind == "shadowsocks" {
		return ssLink(str(o["method"]), str(o["password"]), host, port, name, str(o["plugin"]))
	}
	user := str(o["uuid"])
	switch kind {
	case "vless":
		set(q, "flow", str(o["flow"]))
	case "vmess":
		set(q, "encryption", str(o["security"]))
	case "trojan":
		user = str(o["password"])
	default:
		return ""
	}
	tr := obj(o["transport"])
	network := first(str(tr["type"]), "tcp")
	q.Set("type", network)
	switch network {
	case "ws":
		set(q, "path", str(tr["path"]))
		set(q, "host", header(tr["headers"]))
	case "grpc":
		set(q, "serviceName", str(tr["service_name"]))
	}
	security := "none"
	if yes(tls["enabled"]) {
		security = "tls"
		set(q, "sni", str(tls["server_name"]))
		set(q, "fp", str(obj(tls["utls"])["fingerprint"]))
		set(q, "alpn", list(tls["alpn"]))
		if yes(tls["insecure"]) {
			q.Set("allowInsecure", "1")
		}
		if r := obj(tls["reality"]); yes(r["enabled"]) {
			security = "reality"
			set(q, "pbk", str(r["public_key"]))
			set(q, "sid", str(r["short_id"]))
		}
	}
	q.Set("security", security)
	return link(kind, user, host, port, q, name)
}

// xrayLink reads an Xray outbound in either layout: settings.vnext/servers, or
// the flat settings.address/port/id of newer Xray.
func xrayLink(o map[string]any, remarks string) string {
	kind := strings.ToLower(str(o["protocol"]))
	s := obj(o["settings"])
	srv := s
	if v := arr(s["vnext"]); len(v) > 0 {
		srv = obj(v[0])
	} else if v := arr(s["servers"]); len(v) > 0 {
		srv = obj(v[0])
	}
	u := srv
	if v := arr(srv["users"]); len(v) > 0 {
		u = obj(v[0])
	}
	host, port := str(srv["address"]), str(srv["port"])
	name := str(o["tag"])
	if remarks != "" {
		name = remarks // a config per server: its remarks name it
	}
	if kind == "shadowsocks" {
		return ssLink(str(srv["method"]), str(srv["password"]), host, port, name, "")
	}
	q := url.Values{}
	user := str(u["id"])
	switch kind {
	case "vless":
		set(q, "flow", str(u["flow"]))
	case "vmess":
		set(q, "encryption", str(u["security"]))
	case "trojan":
		user = str(srv["password"])
	default:
		return ""
	}
	st := obj(o["streamSettings"])
	network := first(str(st["network"]), "tcp")
	if network == "splithttp" {
		network = "xhttp"
	}
	q.Set("type", network)
	switch network {
	case "ws":
		w := obj(st["wsSettings"])
		set(q, "path", str(w["path"]))
		set(q, "host", first(str(w["host"]), header(w["headers"])))
	case "grpc":
		g := obj(st["grpcSettings"])
		set(q, "serviceName", str(g["serviceName"]))
		set(q, "authority", str(g["authority"]))
	case "xhttp":
		x := obj(st["xhttpSettings"])
		if x == nil {
			x = obj(st["splithttpSettings"])
		}
		set(q, "path", str(x["path"]))
		set(q, "host", str(x["host"]))
		set(q, "mode", str(x["mode"]))
	}
	security := first(str(st["security"]), "none")
	q.Set("security", security)
	switch security {
	case "tls":
		t := obj(st["tlsSettings"])
		set(q, "sni", str(t["serverName"]))
		set(q, "fp", str(t["fingerprint"]))
		set(q, "alpn", list(t["alpn"]))
		if yes(t["allowInsecure"]) {
			q.Set("allowInsecure", "1")
		}
	case "reality":
		r := obj(st["realitySettings"])
		set(q, "sni", str(r["serverName"]))
		set(q, "fp", str(r["fingerprint"]))
		set(q, "pbk", first(str(r["publicKey"]), str(r["password"])))
		set(q, "sid", str(r["shortId"]))
		set(q, "spx", str(r["spiderX"]))
	}
	return link(kind, user, host, port, q, name)
}

// ssLink is the SIP002 link of a Shadowsocks server; one with a plugin is
// left out (no plugin is carried).
func ssLink(method, password, host, port, name, plugin string) string {
	if plugin != "" || method == "" || password == "" {
		return ""
	}
	return link("ss", base64.RawURLEncoding.EncodeToString([]byte(method+":"+password)), host, port, nil, name)
}

func link(scheme, user, host, port string, q url.Values, name string) string {
	if user == "" || host == "" || port == "" || port == "0" {
		return ""
	}
	u := url.URL{Scheme: scheme, User: url.User(user), Host: net.JoinHostPort(host, port), RawQuery: q.Encode(), Fragment: name}
	return u.String()
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func yes(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "1"
	}
	return false
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func arr(v any) []any {
	a, _ := v.([]any)
	return a
}

// list joins a YAML/JSON list (or takes a comma string) for alpn.
func list(v any) string {
	a, ok := v.([]any)
	if !ok {
		return str(v)
	}
	s := make([]string, 0, len(a))
	for _, x := range a {
		s = append(s, str(x))
	}
	return strings.Join(s, ",")
}

// header takes the Host header of a headers object.
func header(v any) string {
	for k, x := range obj(v) {
		if strings.EqualFold(k, "host") {
			if a := arr(x); len(a) > 0 {
				return str(a[0]) // sing-box allows a list
			}
			return str(x)
		}
	}
	return ""
}

func set(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
