package mobile

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/tsyrenov1987/farvater-core/catalogue"
)

func TestMergeCataloguesStartsFromTheMergedText(t *testing.T) {
	l1 := "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:33443?security=reality&encryption=none&pbk=cV6nKp-RGtPLOht6cg1Up0Tos0qaw8nITDsJCxOKvQk&fp=firefox&sni=www.example.com&sid=0123&flow=xtls-rprx-vision&type=tcp#a"
	l2 := "hysteria2://pw@203.0.113.11:8443?sni=www.example.com&obfs=salamander&obfs-password=x#a"
	texts, _ := json.Marshal([]string{l1, base64.StdEncoding.EncodeToString([]byte(l2)), "not a catalogue"})
	var out struct {
		OK      bool   `json:"ok"`
		Text    string `json:"text"`
		Paths   int    `json:"paths"`
		Skipped int    `json:"skipped"`
	}
	if err := json.Unmarshal([]byte(MergeCatalogues(string(texts))), &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || out.Paths != 2 || out.Skipped != 1 {
		t.Fatalf("%+v", out)
	}
	// What Start will parse: both paths, the clash renamed, the rails and UDP labels kept.
	c, err := catalogue.Parse([]byte(out.Text))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Paths) != 2 || c.Paths[0].ID != "a" || c.Paths[1].ID != "a#2" || c.Paths[1].Spec.ID != "a#2" || !c.Paths[1].Labels.UDP {
		t.Fatalf("%+v", c.Paths)
	}
	var none map[string]any
	_ = json.Unmarshal([]byte(MergeCatalogues(`["nothing here"]`)), &none)
	if none["ok"] != false || none["error"] == "" {
		t.Fatalf("%v", none)
	}
}
