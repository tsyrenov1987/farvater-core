package wire

import (
	"encoding/hex"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/dicttls"
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
func chromeAutoSpec() (utls.ClientHelloSpec, error) { return chromiumSpec(true) }

// edgeAutoSpec is a current Edge's ClientHello, for fp=edge. uTLS's Edge
// profile is Edge 106 (2022). Edge 157.0.4341.57, captured 2026-11-13, sends
// Chrome 157's ClientHello field for field (same suites, groups, key shares,
// ML-DSA signature lead, ALPS, GREASE ECH sizes, shuffle) except that it has no
// trust_anchors extension.
func edgeAutoSpec() (utls.ClientHelloSpec, error) { return chromiumSpec(false) }

// chromiumSpec is the Chrome 133 spec with the current Chromium signature
// lead, plus trust_anchors when the browser sends it (Chrome does, Edge not).
func chromiumSpec(trustAnchors bool) (utls.ClientHelloSpec, error) {
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
	// trust_anchors goes in before the closing GREASE extension, never after it:
	// Chrome keeps GREASE last (uTLS HelloChrome_155 places it the same way), and
	// the shuffle never moves GREASE, so an extension appended after it would sit
	// in the last slot or swap another one there.
	exts := spec.Extensions
	if trustAnchors {
		ta := &utls.GenericExtension{Id: extTrustAnchors, Data: trustAnchorsBody}
		exts = make([]utls.TLSExtension, 0, len(spec.Extensions)+1)
		at := len(spec.Extensions)
		if _, ok := spec.Extensions[at-1].(*utls.UtlsGREASEExtension); ok {
			at--
		}
		exts = append(append(append(exts, spec.Extensions[:at]...), ta), spec.Extensions[at:]...)
	}
	// Shuffle again so trust_anchors lands in a random spot too, the way Chrome
	// places it (the shuffle leaves GREASE, padding and PSK where they are).
	spec.Extensions = utls.ShuffleChromeTLSExtensions(exts)
	return spec, nil
}

// firefoxAutoSpec is the ClientHello of a current Firefox, for fp=firefox.
// uTLS's newest Firefox profile (148) is not what Firefox sends today, in ways a
// passive fingerprint reads: it has no session_ticket or psk_key_exchange_modes,
// offers two CBC suites and two FFDHE groups Firefox dropped, and its GREASE
// ECH is a byte short. This is Firefox 160.0 as captured 2026-11-13 (fresh
// profile, first connection). Firefox keeps a fixed extension order (no
// shuffle) and, like NSS, reuses its X25519 key inside the X25519MLKEM768 share.
func firefoxAutoSpec() utls.ClientHelloSpec {
	return utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768, utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP521AndSHA512, utls.ECDSAWithSHA1,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: append(
				utls.ReuseHybridAndClassicalKeyShares(
					utls.KeyShare{Group: utls.X25519MLKEM768},
					utls.KeyShare{Group: utls.X25519},
				),
				utls.KeyShare{Group: utls.CurveP256},
			)},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256, utls.PSSWithSHA384, utls.PSSWithSHA512,
				utls.PKCS1WithSHA256, utls.PKCS1WithSHA384, utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1, utls.PKCS1WithSHA1,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib, utls.CertCompressionBrotli, utls.CertCompressionZstd,
			}},
			&utls.GREASEEncryptedClientHelloExtension{
				CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
					{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_AES_128_GCM},
					{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_CHACHA20_POLY1305},
				},
				CandidatePayloadLens: []uint16{224}, // +16 tag: the 282-byte extension Firefox 160 sends
			},
		},
	}
}

// uClient is a uTLS client over c whose ClientHello is the browser fp names.
// For the auto Chrome request (fp=chrome or empty) it presents a current
// Chrome via chromeAutoSpec, for fp=edge a current Edge via edgeAutoSpec, for
// fp=firefox a current Firefox via firefoxAutoSpec; any other fp uses uTLS's
// own profile for it.
func uClient(c net.Conn, cfg *utls.Config, fp string) (*utls.UConn, error) {
	if strings.EqualFold(fp, "edge") {
		spec, err := edgeAutoSpec()
		if err != nil {
			return nil, err
		}
		u := utls.UClient(c, cfg, utls.HelloCustom)
		if err := u.ApplyPreset(&spec); err != nil {
			return nil, err
		}
		return u, nil
	}
	if strings.EqualFold(fp, "firefox") {
		spec := firefoxAutoSpec()
		u := utls.UClient(c, cfg, utls.HelloCustom)
		if err := u.ApplyPreset(&spec); err != nil {
			return nil, err
		}
		return u, nil
	}
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
