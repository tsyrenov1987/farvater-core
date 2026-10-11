package wire

import (
	"encoding/hex"
	"net"

	utls "github.com/refraction-networking/utls"
)

// The newest Chrome profile uTLS ships is Chrome 133. A current Chrome (154 at
// the time of writing) sends two things that profile does not, both of which a
// passive TLS fingerprint (JA3/JA4) reads:
//
//   - the trust_anchors extension (0xCA34, draft-ietf-tls-trust-anchor-ids),
//     carrying the certificate-authority identifiers the browser advertises;
//   - a signature_algorithms list that leads with a GREASE value and the three
//     ML-DSA post-quantum schemes.
//
// A fingerprint a year behind the live browser stands out on its own, so
// fp=chrome (and the empty default) present a current Chrome: the Chrome 133
// spec uTLS builds, with those two additions. Everything else — cipher suites,
// curves, key shares, the other extensions, and the per-connection extension
// shuffle Chrome has done since 106 — is Chrome 133's and still matches Chrome
// 154. A link that names an explicit older profile (e.g. fp=hellochrome_131)
// is left exactly as asked.

// Chrome 154's signature_algorithms leads with these before the Chrome 133
// list. The GREASE placeholder is not tied to the connection's GREASE seed (it
// sits in a field uTLS does not reseed), which a JA3/JA4 hash does not see: it
// drops GREASE before hashing. ML-DSA codepoints are draft-tls-westerbaan-mldsa.
var chrome154SigAlgLead = []utls.SignatureScheme{
	utls.GREASE_PLACEHOLDER,
	0x0904, // mldsa44
	0x0905, // mldsa65
	0x0906, // mldsa87
}

// extTrustAnchors is the trust_anchors extension type.
const extTrustAnchors uint16 = 0xca34

// trustAnchorsBody is the body of Chrome 154's trust_anchors extension: the set
// of CA identifiers it advertises. It comes from the browser build, not the
// connection — identical in every Chrome 154 ClientHello — so it is a constant.
// Captured 2026-10-11 from Chrome 154.0.8037.98.
var trustAnchorsBody = mustHexDecode("" +
	"00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f" +
	"0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c" +
	"9b2d010808839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08" +
	"839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d011208839a648c9b" +
	"2d011304d679090104d679090404d679090504d679090604d679090704d67909" +
	"0804d679090a04d679090b04d679090c04d679090d04d679090f")

func mustHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("wire: bad trust-anchors literal: " + err.Error())
	}
	return b
}

// chromeAutoSpec is the Chrome 154 ClientHello: the Chrome 133 spec with the
// two Chrome 154 additions. It is built fresh each call, so its GREASE values
// and extension order are chosen per connection, as Chrome's are.
func chromeAutoSpec() (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		return spec, err
	}
	for _, e := range spec.Extensions {
		if sa, ok := e.(*utls.SignatureAlgorithmsExtension); ok {
			sa.SupportedSignatureAlgorithms = append(
				append([]utls.SignatureScheme{}, chrome154SigAlgLead...),
				sa.SupportedSignatureAlgorithms...)
		}
	}
	exts := append(spec.Extensions, &utls.GenericExtension{Id: extTrustAnchors, Data: trustAnchorsBody})
	// Shuffle again so trust_anchors lands in a random spot too, the way Chrome
	// places it (the shuffle leaves GREASE, padding and PSK where they are).
	spec.Extensions = utls.ShuffleChromeTLSExtensions(exts)
	return spec, nil
}

// uClient is a uTLS client over c whose ClientHello is the browser fp names.
// For the auto Chrome request (fp=chrome or empty) it presents a current
// Chrome via chromeAutoSpec; any other fp uses uTLS's own profile for it.
func uClient(c net.Conn, cfg *utls.Config, fp string) (*utls.UConn, error) {
	if !isChromeAuto(fp) {
		return utls.UClient(c, cfg, clientHello(fp)), nil
	}
	spec, err := chromeAutoSpec()
	if err != nil {
		return nil, err
	}
	u := utls.UClient(c, cfg, utls.HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	return u, nil
}
