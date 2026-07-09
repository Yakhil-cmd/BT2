# Q1998: Mix ciphersuite domains

## Question
Can an unprivileged caller and, where needed, a single malicious participant below threshold enter through `lib::reshare(...)` and exploit `reshare` so `reshare` derived for one ciphersuite, proof role, or transcript label is accepted in another domain, causing Cryptographic flaws?

## Target
- File/function: `src/lib.rs::reshare`
- Entrypoint: `lib::reshare(...)`
- Attacker controls: `old_participants`, `new_participants`, `old_threshold`, `new_threshold`
- Exploit idea: Create a domain or ciphersuite mix where `reshare` material from one role verifies in another.
- Invariant to test: Ciphersuite-specific `reshare` derivations must not collide across domains or protocol roles.
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: Construct a deterministic unit or invariant test around `lib::reshare` that feeds crafted `reshare` / `derived verifying key` inputs, then assert whether downstream verification accepts an output that should have been rejected.
