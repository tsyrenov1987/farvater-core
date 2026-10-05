package catalogue

import (
	"encoding/base64"
	"strings"
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

func TestMergePoolsPathsAndKeepsIDsApart(t *testing.T) {
	l3 := "hysteria2://pw@203.0.113.12:8443?sni=www.example.com#a"
	first, err := Parse([]byte(`{"v":1,"title":"one","paths":[{"uri":"` + l1 + `"}],"probe_urls":["https://example.org/1"],"priors":{"cell":{"a":{"a":3,"b":1}}},"feedback_url":"https://one.example/fb","refresh_sec":600}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Parse([]byte(l3 + "\n" + l1 + "\n" + l2))
	if err != nil {
		t.Fatal(err)
	}
	second.Priors = map[string]map[string]Prior{"cell": {"a": {A: 7, B: 2}, "gone": {A: 1, B: 1}}}
	second.ProbeURLs = []string{"https://example.org/1", "https://example.org/2"}
	m := Merge([]*Catalogue{first, second})
	var ids []string
	for _, e := range m.Paths {
		if e.Spec.ID != e.ID {
			t.Fatalf("spec id %q for path %q", e.Spec.ID, e.ID)
		}
		ids = append(ids, e.ID)
	}
	// l1 is in both: once. Second's "a" (l3) clashes with first's "a": a#2, with its prior.
	if strings.Join(ids, ",") != "a,a#2,b" {
		t.Fatalf("ids %v", ids)
	}
	if m.Priors["cell"]["a"].A != 3 || m.Priors["cell"]["a#2"].A != 7 || len(m.Priors["cell"]) != 2 {
		t.Fatalf("priors %+v", m.Priors)
	}
	if m.Title != "one" || m.RefreshSec != 600 || m.FeedbackURL != "" || len(m.ProbeURLs) != 2 {
		t.Fatalf("%+v", m)
	}
	if Merge([]*Catalogue{first}).FeedbackURL != "https://one.example/fb" {
		t.Fatal("a single catalogue keeps its feedback URL")
	}
}
