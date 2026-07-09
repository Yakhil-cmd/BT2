# Q2257: Iterate toward hidden state

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and make repeated attacker-chosen queries around `commit_polynomial` so the returned `commit` or `polynomial` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/polynomials.rs::commit_polynomial`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `polynomial`, `polynomial commitment`
- Exploit idea: Collect many attacker-chosen outputs that depend on `commit` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `commit` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::commit_polynomial` that feeds crafted `commit` / `polynomial` inputs, then assert whether downstream verification accepts an output that should have been rejected.
