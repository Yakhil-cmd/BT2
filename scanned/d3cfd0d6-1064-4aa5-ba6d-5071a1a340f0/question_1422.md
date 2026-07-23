# Q1422: decodeU256 RLP differential decode

## Question
Can an unprivileged attacker reach `decodeU256` through RLP stream or raw-value decoding of network or transaction payloads using non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings and make `decodeU256` decode the same raw bytes into different semantic values in different callers, causing the invariant that every accepted RLP byte string must decode to one canonical semantic object everywhere it is used to fail and leading to Transaction manipulation?

## Target
- File/function: rlp/decode.go:255 (decodeU256)
- Entrypoint: RLP stream or raw-value decoding of network or transaction payloads
- Attacker controls: non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings
- Exploit idea: make `decodeU256` decode the same raw bytes into different semantic values in different callers
- Invariant to test: every accepted RLP byte string must decode to one canonical semantic object everywhere it is used
- Expected Immunefi impact: Transaction manipulation
- Fast validation: replay the same crafted RLP payload through all callers and assert signer, hash, and semantic fields stay identical
