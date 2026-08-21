# Q2269: derived id parsing in universal_state_init::to_raw

## Question
Can an unprivileged attacker who creates implicit or deterministic accounts by transferring to attacker-derived account ids, controlling account id bytes at the length, charset and separator boundaries, drive `core/primitives/src/universal_state_init.rs::to_raw` to have derivation and validation disagree about the same id, breaking the invariant that an id accepted by derivation is accepted identically everywhere else, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/primitives/src/universal_state_init.rs` -> `to_raw`
- Entrypoint: unprivileged attacker creates implicit or deterministic accounts by transferring to attacker-derived account ids
- Attacker controls: account id bytes at the length, charset and separator boundaries
- Exploit idea: have derivation and validation disagree about the same id
- Invariant to test: an id accepted by derivation is accepted identically everywhere else
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
