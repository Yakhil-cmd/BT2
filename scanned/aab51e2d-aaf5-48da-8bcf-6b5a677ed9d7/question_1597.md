# Q1597: engine accounting and storage empty-account illusion at code reads and writes in `set_code`, `remove_code`, and `get_code`

## Question
Can an attacker cause code reads and writes in `set_code`, `remove_code`, and `get_code` to treat an account as empty when another component still sees value, code, or storage there, leading to Temporary freezing of funds?

## Target
- File/function: `engine/src/engine.rs + engine/src/accounting.rs + engine/src/state.rs` -> `code reads and writes in `set_code`, `remove_code`, and `get_code``
- Entrypoint: unprivileged `submit()`, `submit_with_args()`, `call()`, `deploy_code()`, connector methods, and precompile-triggered flows that reach core state updates
- Attacker controls: public transaction calldata, deployment input, transfer values, storage keys, bridge amounts, refund timing, and any reachable user-controlled addresses
- Exploit idea: attack empty-account checks and their companion state reads.
- Invariant to test: core balance, nonce, code, storage-generation, and token-registration state must stay internally consistent across every public execution path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Craft addresses with only one facet populated and assert emptiness checks align with every consumer. add integration tests that exercise the public path to the targeted helper, then assert balances, nonces, code bytes, storage keys, and mappings remain internally consistent
