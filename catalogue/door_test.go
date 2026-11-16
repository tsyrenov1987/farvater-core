package catalogue

import "testing"

func TestDoorLabel(t *testing.T) {
	c, err := Parse([]byte("#door=cdnv\n#net=cell\n#white\nvless://u@78.159.245.140:443?security=tls&type=xhttp#Orden-ru8\nvless://u@1.1.1.1:443?security=tls&type=xhttp#de3\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l := c.Paths[0].Labels; l.Door != "cdnv" || !l.White || l.Net != "cell" {
		t.Fatalf("labels: %+v", l)
	}
	if c.Paths[1].Labels.Door != "" {
		t.Fatal("door leaked to the next line")
	}
}
