# Q2792: PublicKeyFromBytes signature parser ambiguity

## Question
Can an unprivileged attacker reach `PublicKeyFromBytes` through transaction, consensus, or bridge signature bytes reaching validation code using signature bytes, public-key bytes, message hashes, proof bytes, and alternate encodings and make `PublicKeyFromBytes` parse a byte sequence as a valid authorization under one path but a different authorization under another, causing the invariant that signature parsing must be canonical and stable across every caller that relies on it to fail and leading to Unauthorized transaction?

## Target
- File/function: crypto/bls/blst/public_key.go:30 (PublicKeyFromBytes)
- Entrypoint: transaction, consensus, or bridge signature bytes reaching validation code
- Attacker controls: signature bytes, public-key bytes, message hashes, proof bytes, and alternate encodings
- Exploit idea: make `PublicKeyFromBytes` parse a byte sequence as a valid authorization under one path but a different authorization under another
- Invariant to test: signature parsing must be canonical and stable across every caller that relies on it
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: feed the same signature bytes into every reachable validation path and assert recovered identity never diverges
