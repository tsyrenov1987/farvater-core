package mobile

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestImportCatalogueKeepsTheLinkItFound(t *testing.T) {
	l1 := "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:33443?security=reality&encryption=none&pbk=cV6nKp-RGtPLOht6cg1Up0Tos0qaw8nITDsJCxOKvQk&fp=firefox&sni=www.example.com&sid=0123&flow=xtls-rprx-vision&type=tcp#a"
	l2 := "hysteria2://pw@203.0.113.11:8443?sni=www.example.com&obfs=salamander&obfs-password=x#b"
	body := base64.StdEncoding.EncodeToString([]byte(l1 + "\n" + l2))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/s/abc" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, body)
	}))
	defer srv.Close()
	link := srv.URL + "/s/abc"

	type result struct {
		OK     bool   `json:"ok"`
		Source string `json:"source"`
		Text   string `json:"text"`
		Paths  int    `json:"paths"`
		Error  string `json:"error"`
	}
	imp := func(in string) (r result) {
		if err := json.Unmarshal([]byte(ImportCatalogue(in)), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	// A link inside another client's import link or a message: the link is what
	// the app keeps (and refreshes from), the body what it starts from.
	for _, in := range []string{link, "happ://add/" + link, "Ваша подписка: " + link + "."} {
		if r := imp(in); !r.OK || r.Source != link || r.Text != body || r.Paths != 2 {
			t.Fatalf("%q: %+v", in, r)
		}
	}
	// Share links pasted as they are: kept as the text itself.
	if r := imp(" " + l1 + "\n"); !r.OK || r.Source != l1 || r.Text != l1 || r.Paths != 1 {
		t.Fatalf("share link: %+v", r)
	}
	if r := imp(srv.URL + "/s/gone"); r.OK || !strings.Contains(r.Error, "HTTP 404") {
		t.Fatalf("missing subscription: %+v", r)
	}
	if r := imp("просто текст"); r.OK || r.Error == "" {
		t.Fatalf("text: %+v", r)
	}
}
