package service

import (
	"regexp"
	"strings"
)

// DoorSpec names the catalogue's doors a build knows besides the brand's own
// names. It is given at build time,
//
//	go build -ldflags "-X github.com/tsyrenov1987/farvater-core/service.DoorSpec=<spec>"
//
// as a comma-separated list of
//
//	door=https://host/api  a name without the brand that serves the catalogue
//	                       under /api; the doors are tried first, in order
//	host=name              another name of the brand's catalogue, tried after
//	                       the doors and accepted in a subscription link
//	txt=name               the TXT record holding the signed list of doors
//	key=base64             the public half (PKIX DER) of the key signing it
//
// The doors are left out of this source: a name in a public repository next
// to the brand is the first one a censor reads. A build without DoorSpec
// fetches from the brand's names alone.
var DoorSpec string

var (
	plainDoors   []string
	serviceHosts []string
	signedName   string
	signedKey    string
	ordenURL     *regexp.Regexp
)

func init() { setDoors(DoorSpec) }

// setDoors takes spec as DoorSpec; tests give their own.
func setDoors(spec string) {
	plainDoors, serviceHosts, signedName, signedKey = nil, nil, "", ""
	hosts := []string{`joinorden\.com`, `myorden\.ru`}
	for _, item := range strings.Split(spec, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(item), "=")
		switch k {
		case "door":
			plainDoors = append(plainDoors, strings.TrimRight(v, "/"))
		case "host":
			serviceHosts = append(serviceHosts, strings.ToLower(v))
			hosts = append(hosts, regexp.QuoteMeta(strings.ToLower(v)))
		case "txt":
			signedName = v
		case "key":
			signedKey = v
		}
	}
	ordenURL = regexp.MustCompile(`(?i)^https://(?:www\.)?(?:` + strings.Join(hosts, "|") + `)(/\S*)$`)
}
