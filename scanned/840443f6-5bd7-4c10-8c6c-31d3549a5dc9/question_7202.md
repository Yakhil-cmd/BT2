# Q7202: decodeU256 blob or proof binding gap

## Question
Can an unprivileged attacker reach `decodeU256` through blob or KZG proof verification path using non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings and make `decodeU256` verify a proof for one blob while later execution consumes another blob, causing the invariant that a verified proof must bind exactly one executable blob payload and commitment to fail and leading to Fee payment bypass?

## Target
- File/function: rlp/decode.go:255 (decodeU256)
- Entrypoint: blob or KZG proof verification path
- Attacker controls: non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings
- Exploit idea: make `decodeU256` verify a proof for one blob while later execution consumes another blob
- Invariant to test: a verified proof must bind exactly one executable blob payload and commitment
- Expected Immunefi impact: Fee payment bypass
- Fast validation: swap blob payloads after successful proof validation and assert downstream consumers reject the mismatch
