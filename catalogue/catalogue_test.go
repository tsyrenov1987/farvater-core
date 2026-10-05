package catalogue

import (
	"encoding/base64"
	"testing"
)

const l1 = "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:33443?security=reality&encryption=none&pbk=cV6nKp-RGtPLOht6cg1Up0Tos0qaw8nITDsJCxOKvQk&fp=firefox&sni=www.example.com&sid=0123&flow=xtls-rprx-vision&type=tcp#a"
const l2 = "hysteria2://pw@203.0.113.11:8443?sni=www.example.com&obfs=salamander&obfs-password=x#b"

func TestParseBase64Subscription(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte(l1 + "\n" + l2 + "\nss://unsupported@x:1#c\n"))
	c, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Paths) != 2 || c.Paths[0].ID != "a" || c.Paths[1].Labels.Rail != "hy2" || !c.Paths[1].Labels.UDP {
		t.Fatalf("%+v", c.Paths)
	}
}

func TestParseJSONCatalogue(t *testing.T) {
	body := `{"v":1,"title":"t","paths":[{"id":"p1","uri":"` + l1 + `","labels":{"white":true,"budget_bytes":5}}],"probe_urls":["https://example.org/256k"],"priors":{"cell":{"p1":{"a":3,"b":1}}}}`
	c, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if c.Paths[0].Spec.ID != "p1" || c.Paths[0].Labels.Rail != "reality" || !c.Paths[0].Labels.White || c.Priors["cell"]["p1"].A != 3 {
		t.Fatalf("%+v", c)
	}
}
