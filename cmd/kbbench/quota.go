package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/pion/turn/v5"
	"github.com/tsyrenov1987/farvater-core/vkturn"
	"github.com/tsyrenov1987/farvater-core/wire"
)

// quota opens allocations with each of the link's TURN credentials, one after
// another, until the relay refuses or max is reached, holds them for hold, and
// lets them all go. It answers how many allocations one account may hold.
// With pool set (a directory of the gateway pool's q*.json files) the accounts
// come from there instead of the link, and each is let go before the next.
func quota(spec wire.PathSpec, max int, hold time.Duration, pool string) {
	var t *wire.TURNSpec
	for _, s := range append([]wire.PathSpec{spec}, spec.Legs...) {
		if s.TURN != nil {
			t = s.TURN
			break
		}
	}
	enc := json.NewEncoder(os.Stdout)
	if pool != "" {
		t = &wire.TURNSpec{}
		files, _ := filepath.Glob(filepath.Join(pool, "*.json"))
		for _, f := range files {
			var acc struct {
				Turn []struct{ Address, Username, Password string } `json:"turn"`
			}
			if b, err := os.ReadFile(f); err == nil && json.Unmarshal(b, &acc) == nil {
				for _, c := range acc.Turn {
					t.Creds = append(t.Creds, vkturn.Creds{Address: c.Address, Username: c.Username, Password: c.Password})
				}
			}
		}
	}
	if t == nil {
		enc.Encode(map[string]any{"err": "no TURN leg in the link"})
		return
	}
	type held struct {
		pc net.PacketConn
		cl *turn.Client
		rc net.PacketConn
	}
	var all []held
	release := func() {
		for _, h := range all {
			h.rc.Close()
			h.cl.Close()
			h.pc.Close()
		}
		all = nil
	}
	for _, cr := range t.Creds {
		sum := sha256.Sum256([]byte(cr.Username))
		got, why := 0, ""
		for got < max {
			pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
			if err != nil {
				why = err.Error()
				break
			}
			cl, err := turn.NewClient(&turn.ClientConfig{STUNServerAddr: cr.Address, TURNServerAddr: cr.Address,
				Username: cr.Username, Password: cr.Password, Conn: pc})
			if err == nil {
				err = cl.Listen()
			}
			var rc net.PacketConn
			if err == nil {
				rc, err = cl.Allocate()
			}
			if err != nil {
				why = err.Error()
				if cl != nil {
					cl.Close()
				}
				pc.Close()
				break
			}
			all = append(all, held{pc, cl, rc})
			got++
		}
		enc.Encode(map[string]any{"relay": cr.Address, "user": hex.EncodeToString(sum[:3]), "got": got, "stopped": why})
		if pool != "" {
			release()
		}
	}
	time.Sleep(hold)
	release()
	time.Sleep(300 * time.Millisecond)
}
