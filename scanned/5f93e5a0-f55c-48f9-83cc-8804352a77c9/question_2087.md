# Q2087: derivation collision in universal_account_id::hrp_expanded

## Question
Can an unprivileged attacker who creates implicit or deterministic accounts by transferring to attacker-derived account ids, controlling the seed, salt and owner bytes feeding deterministic account derivation, drive `core/primitives-core/src/universal_account_id.rs::hrp_expanded` to derive one account id from two distinct inputs, or capture an id another user expects, breaking the invariant that account derivation is injective over its inputs, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `core/primitives-core/src/universal_account_id.rs` -> `hrp_expanded`
- Entrypoint: unprivileged attacker creates implicit or deterministic accounts by transferring to attacker-derived account ids
- Attacker controls: the seed, salt and owner bytes feeding deterministic account derivation
- Exploit idea: derive one account id from two distinct inputs, or capture an id another user expects
- Invariant to test: account derivation is injective over its inputs
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
