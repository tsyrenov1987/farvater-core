package main

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/tsyrenov1987/farvater-core/catalogue"
	"github.com/tsyrenov1987/farvater-core/desktop"
)

func TestCatalogueURLs(t *testing.T) {
	u, err := catalogueURLs(" orden-ABCDE-12345 ")
	if err != nil || len(u) != len(catalogueHosts) || u[0] != "https://viporden.online/hsub/ORDEN-ABCDE-12345" {
		t.Fatalf("code: %v %v", u, err)
	}
	if u, err = catalogueURLs("https://x.example/sub/1"); err != nil || len(u) != 1 {
		t.Fatalf("url: %v %v", u, err)
	}
	if _, err = catalogueURLs("http://x"); err == nil {
		t.Fatal("http must be refused")
	}
}

func TestExplain(t *testing.T) {
	// The line the worker's pcGateResponse sends, base64 as on the wire.
	const stub = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?encryption=none&type=tcp#%F0%9F%92%BB"
	_, err := catalogue.Parse([]byte(base64.StdEncoding.EncodeToString([]byte(stub))))
	if err == nil {
		t.Fatal("the placeholder must not parse as a path")
	}
	for _, c := range []struct {
		err  error
		want string
	}{
		{err, "тарифах"},
		{errors.New("catalogue: HTTP 404"), "кода нет"},
		{errors.New("catalogue: HTTP 403"), "закончился"},
		{errors.New("catalogue: HTTP 409"), "устройства"},
	} {
		got := desktop.Explain(c.err)
		if got == nil || !strings.Contains(got.Error(), c.want) {
			t.Errorf("%v: %v", c.err, got)
		}
	}
	for _, e := range []error{errors.New("catalogue: HTTP 503"), errors.New("read: connection reset by peer")} {
		if got := desktop.Explain(e); got != nil {
			t.Errorf("%v must say nothing about the code: %v", e, got)
		}
	}
}
