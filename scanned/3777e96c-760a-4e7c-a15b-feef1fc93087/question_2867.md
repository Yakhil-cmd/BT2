# Q2867: decodeU256 signature parser ambiguity

## Question
Can an unprivileged attacker reach `decodeU256` through transaction, consensus, or bridge signature bytes reaching validation code using non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings and make `decodeU256` parse a byte sequence as a valid authorization under one path but a different authorization under another, causing the invariant that signature parsing must be canonical and stable across every caller that relies on it to fail and leading to Unauthorized transaction?

## Target
- File/function: rlp/decode.go:255 (decodeU256)
- Entrypoint: transaction, consensus, or bridge signature bytes reaching validation code
- Attacker controls: non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings
- Exploit idea: make `decodeU256` parse a byte sequence as a valid authorization under one path but a different authorization under another
- Invariant to test: signature parsing must be canonical and stable across every caller that relies on it
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: feed the same signature bytes into every reachable validation path and assert recovered identity never diverges
