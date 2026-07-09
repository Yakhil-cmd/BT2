# Q2231: Iterate toward hidden state

## Question
Can a malicious participant below threshold enter through `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)` and make repeated attacker-chosen queries around `batch_invert` so the returned `invert` or `Lagrange coefficient` values reveal linear information about hidden shares or nonce material over time, causing Information disclosure of sensitive MPC state?

## Target
- File/function: `src/crypto/polynomials.rs::batch_invert`
- Entrypoint: `keygen(...)`, `reshare(...)`, `refresh(...)`, `presign(...)`, `sign(...)`, or `ckd(...)`
- Attacker controls: `values`
- Exploit idea: Collect many attacker-chosen outputs that depend on `invert` and test whether linear relations reveal hidden shares or nonce structure over time.
- Invariant to test: Public-facing return values derived from `invert` must not allow iterative reconstruction of hidden state across repeated queries.
- Expected Immunefi impact: Information disclosure of sensitive MPC state
- Fast validation: Construct a deterministic unit or invariant test around `crypto::polynomials::batch_invert` that feeds crafted `invert` / `Lagrange coefficient` inputs, then assert whether downstream verification accepts an output that should have been rejected.
