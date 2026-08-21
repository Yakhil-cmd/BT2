# Q2090: derived id parsing in universal_account_id::verify_checksum

## Question
Can an unprivileged attacker who creates implicit or deterministic accounts by transferring to attacker-derived account ids, controlling account id bytes at the length, charset and separator boundaries, drive `core/primitives-core/src/universal_account_id.rs::verify_checksum` to have derivation and validation disagree about the same id, breaking the invariant that an id accepted by derivation is accepted identically everywhere else, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/primitives-core/src/universal_account_id.rs` -> `verify_checksum`
- Entrypoint: unprivileged attacker creates implicit or deterministic accounts by transferring to attacker-derived account ids
- Attacker controls: account id bytes at the length, charset and separator boundaries
- Exploit idea: have derivation and validation disagree about the same id
- Invariant to test: an id accepted by derivation is accepted identically everywhere else
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
