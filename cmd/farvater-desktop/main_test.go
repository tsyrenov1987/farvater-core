package main

import "testing"

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
