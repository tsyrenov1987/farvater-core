package wire

import (
	"encoding/binary"
	"errors"
)

// This core touches protocol-buffer bytes in only two tiny places: the gRPC
// Hunk message (field 1, the tunnel bytes) and the VLESS addons (field 1, the
// flow name). Both are a single length-delimited field, so a few lines of the
// wire format replace a protobuf runtime.

// appendVarint appends x in base-128 varint form.
func appendVarint(b []byte, x uint64) []byte {
	for x >= 0x80 {
		b = append(b, byte(x)|0x80)
		x >>= 7
	}
	return append(b, byte(x))
}

// appendVarintField appends a length-delimited field (wire type 2): the tag,
// the length, then the bytes.
func appendVarintField(b []byte, field int, data []byte) []byte {
	b = appendVarint(b, uint64(field)<<3|2)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

// readVarint reads one varint and returns it with the rest of b.
func readVarint(b []byte) (uint64, []byte, error) {
	v, n := binary.Uvarint(b)
	if n <= 0 {
		return 0, b, errors.New("protowire: bad varint")
	}
	return v, b[n:], nil
}
