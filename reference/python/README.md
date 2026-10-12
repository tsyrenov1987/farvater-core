# Kilvater — Python reference implementation

A second, independent implementation of the [Kilvater](../../docs/KILVATER.md) wire format, written from
the spec in Python with no third-party dependencies. Its job is to **pin the spec**: it is cross-checked in
CI against the Go reference using shared golden vectors, so the two implementations are proven to agree byte
for byte.

- `kilvater.py` — the format: the request tag (v1 and v2), the v2 key derivation (key id + HKDF-SHA256), the
  frame codec, and the address encoding. It also implements the stateless accept checks (window, path, MAC,
  revocation).
- `test_vectors.py` — loads [`kilvater/testdata/vectors.json`](../../kilvater/testdata/vectors.json) and
  asserts this implementation reproduces every vector from the frozen inputs.

It does **not** implement TLS 1.3 or HTTP/2 — those layers are standard libraries in any real client, and
Kilvater adds no cipher of its own ([spec §1](../../docs/KILVATER.md#1-layers)). This is a reference for the
format, not a production transport. The server-side replay cache (spec §3) is stateful and out of scope here.

## Run

```sh
python3 -m unittest discover -s reference/python -v
```

The Go side checks the same golden file in `go test ./...`; regenerate the golden after a deliberate protocol
change with `KV_UPDATE_VECTORS=1 go test ./kilvater -run TestVectors`.
