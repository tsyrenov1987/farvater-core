// Package catalogue loads the list of paths: either the open JSON catalogue
// (see docs/CATALOGUE-SPEC.md) or a plain base64 subscription of share links.
package catalogue

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tsyrenov1987/farvater-core/wire"
)

// Labels are the optional per-path hints of the JSON catalogue.
type Labels struct {
	Rail        string `json:"rail,omitempty"`
	Net         string `json:"net,omitempty"`
	White       bool   `json:"white,omitempty"`
	BudgetBytes int64  `json:"budget_bytes,omitempty"`
	UDP         bool   `json:"udp,omitempty"`
}

// Entry is one path of the catalogue.
type Entry struct {
	ID     string        `json:"id"`
	URI    string        `json:"uri"`
	Labels Labels        `json:"labels"`
	Spec   wire.PathSpec `json:"-"`
}

// Prior is a weak Beta prior for one path in one context.
type Prior struct {
	A float64 `json:"a"`
	B float64 `json:"b"`
}

// Catalogue is the parsed document.
type Catalogue struct {
	V           int                         `json:"v"`
	Title       string                      `json:"title"`
	Fingerprint string                      `json:"fingerprint"`
	Paths       []Entry                     `json:"paths"`
	ProbeURLs   []string                    `json:"probe_urls"`
	Priors      map[string]map[string]Prior `json:"priors"`
	FeedbackURL string                      `json:"feedback_url"`
	RefreshSec  int                         `json:"refresh_sec"`
	Source      string                      `json:"-"`
}

// Load reads a catalogue from a URL or a local file path.
func Load(src string) (*Catalogue, error) {
	var body []byte
	var err error
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		body, err = fetch(src)
	} else {
		body, err = os.ReadFile(src)
	}
	if err != nil {
		return nil, err
	}
	c, err := Parse(body)
	if err != nil {
		return nil, err
	}
	c.Source = src
	return c, nil
}

func fetch(u string) ([]byte, error) {
	cl := &http.Client{Timeout: 20 * time.Second}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "farvater-core/0.1")
	req.Header.Set("Accept", "application/farvater-catalogue+json, text/plain;q=0.9, */*;q=0.5")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("catalogue: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// Parse accepts the JSON catalogue, a base64 subscription, or plain share links.
func Parse(body []byte) (*Catalogue, error) {
	t := strings.TrimSpace(string(body))
	if strings.HasPrefix(t, "{") {
		var c Catalogue
		if err := json.Unmarshal([]byte(t), &c); err != nil {
			return nil, fmt.Errorf("catalogue json: %w", err)
		}
		for i := range c.Paths {
			s, err := wire.ParseURI(c.Paths[i].URI)
			if err != nil {
				return nil, fmt.Errorf("path %s: %w", c.Paths[i].ID, err)
			}
			if c.Paths[i].ID != "" {
				s.ID = c.Paths[i].ID
			} else {
				c.Paths[i].ID = s.ID
			}
			c.Paths[i].Spec = s
			if c.Paths[i].Labels.Rail == "" {
				c.Paths[i].Labels.Rail = s.Rail()
			}
		}
		return &c, nil
	}
	if !strings.Contains(t, "://") {
		dec, err := decodeB64(t)
		if err != nil {
			return nil, errors.New("catalogue: neither JSON, nor share links, nor base64")
		}
		t = string(dec)
	}
	c := &Catalogue{V: 1, Title: "subscription"}
	sc := bufio.NewScanner(strings.NewReader(t))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	seen := map[string]int{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s, err := wire.ParseURI(line)
		if err != nil {
			continue // unsupported scheme or malformed: skip, never fail the whole list
		}
		seen[s.ID]++
		if seen[s.ID] > 1 {
			s.ID = fmt.Sprintf("%s#%d", s.ID, seen[s.ID])
		}
		c.Paths = append(c.Paths, Entry{ID: s.ID, URI: line, Labels: Labels{Rail: s.Rail(), UDP: s.Kind == wire.KindHysteria2}, Spec: s})
	}
	if len(c.Paths) == 0 {
		return nil, errors.New("catalogue: no supported paths")
	}
	return c, nil
}

func decodeB64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("base64")
}
