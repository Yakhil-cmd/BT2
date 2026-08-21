# Q1960: curve point validation in signature::ml_dsa_65_secret_from_keypair

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling points off the curve, in the wrong subgroup, or at infinity, drive `core/crypto/src/signature.rs::ml_dsa_65_secret_from_keypair` to have a pairing or scalar-multiplication host call accept an invalid point, breaking the invariant that every curve input is validated for curve and subgroup membership before use, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `core/crypto/src/signature.rs` -> `ml_dsa_65_secret_from_keypair`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: points off the curve, in the wrong subgroup, or at infinity
- Exploit idea: have a pairing or scalar-multiplication host call accept an invalid point
- Invariant to test: every curve input is validated for curve and subgroup membership before use
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: extend the existing wasm fuzz target and assert no panic and identical gas across two runs
