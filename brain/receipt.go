// Package brain is the decision core of farvater-core: it turns delivery
// receipts of real connections into path choices. It contains no networking.
package brain

// End says how a flow ended.
type End uint8

const (
	EndRemoteFin    End = iota // the remote side finished normally
	EndLocalClose              // the local app closed the flow
	EndWireReset               // the transport reset the flow
	EndStallAbandon            // the app gave up inside a stall window
	EndTimeout                 // no wire or no first byte in time
)

func (e End) String() string {
	switch e {
	case EndRemoteFin:
		return "remote_fin"
	case EndLocalClose:
		return "local_close"
	case EndWireReset:
		return "wire_reset"
	case EndStallAbandon:
		return "stall_abandon"
	case EndTimeout:
		return "timeout"
	}
	return "?"
}

// DstClass is a coarse class of the destination, used for exploration policy.
type DstClass uint8

const (
	DstOther DstClass = iota
	DstTLS443
	DstDNS
	DstQUIC
)

const (
	KB            = int64(1024)
	DeliverBytes  = 32 * KB  // "delivered" for a flow the app closed itself
	EvidenceBytes = 16 * KB  // below this a finished flow proves only the first byte
	BigBytes      = 256 * KB // above this a flow also measures goodput
	Cut16Lo       = 12 * KB  // cut signature window
	Cut16Hi       = 28 * KB
)

// Receipt is the unit of evidence: what one real flow experienced on one path.
// Times are relative to the flow start unless stated otherwise.
type Receipt struct {
	Path        string
	Ctx         string
	AtMs        int64 // absolute time the receipt became final
	WireReadyMs int64 // -1: the wire never connected
	FirstByteMs int64 // -1: no downstream byte
	Up, Down    int64
	DurMs       int64
	MaxGapMs    int64
	Stalls      int
	End         End
	DownAtFail  int64 // -1: n/a
	Dst         string
	DstClass    DstClass
	Explore     bool
}

// FirstByte reports whether the destination answered through this path.
func (r Receipt) FirstByte() bool { return r.FirstByteMs >= 0 }

// Sig is the block signature the breaker reads out of the receipt; SigNone
// when nothing in it points at interference.
func (r Receipt) Sig() BlockSig { return classify(r) }

// Delivered reports whether the flow is proof of delivery.
func (r Receipt) Delivered() bool {
	if r.Stalls > 0 || !r.FirstByte() {
		return false
	}
	switch r.End {
	case EndRemoteFin:
		return r.Down >= KB
	case EndLocalClose:
		return r.Down >= DeliverBytes
	}
	return false
}

// DelivEvidence is the flow's vote for the delivery posterior: +1, -1 or 0 (neutral).
func (r Receipt) DelivEvidence() int {
	if !r.FirstByte() {
		return 0
	}
	if r.Stalls > 0 {
		return -1
	}
	switch r.End {
	case EndWireReset, EndTimeout, EndStallAbandon:
		return -1
	case EndRemoteFin:
		if r.Down >= EvidenceBytes {
			return 1
		}
	case EndLocalClose:
		if r.Down >= DeliverBytes {
			return 1
		}
	}
	return 0
}

// FbEvidence is the flow's vote for the first-byte posterior.
func (r Receipt) FbEvidence() int {
	if r.FirstByte() {
		return 1
	}
	if r.End == EndLocalClose {
		return 0
	}
	return -1
}
