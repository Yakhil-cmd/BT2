# Q2154: Iterate toward hidden state

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and make repeated attacker-chosen queries around `domain_separate_hash` so the returned `domain-separated hash` or `polynomial commitment` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/hash.rs::domain_separate_hash`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `domain_separator`, `data`
- Exploit idea: Collect many attacker-chosen outputs that depend on `domain-separated hash` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `domain-separated hash` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::hash::domain_separate_hash` that feeds crafted `domain-separated hash` / `polynomial commitment` inputs, then assert whether downstream verification accepts an output that should have been rejected.
