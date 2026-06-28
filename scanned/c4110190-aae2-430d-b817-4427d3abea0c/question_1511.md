# Q1511: engine accounting and storage duplicate key state around ERC-20 registration in `register_token`

## Question
Can an attacker make ERC-20 registration in `register_token` install, remove, or interpret function-call-key state inconsistently across public actions, letting old authorization survive or new authorization disappear and causing Permanent freezing of funds?

## Target
- File/function: `engine/src/engine.rs + engine/src/accounting.rs + engine/src/state.rs` -> `ERC-20 registration in `register_token``
- Entrypoint: unprivileged `submit()`, `submit_with_args()`, `call()`, `deploy_code()`, connector methods, and precompile-triggered flows that reach core state updates
- Attacker controls: public transaction calldata, deployment input, transfer values, storage keys, bridge amounts, refund timing, and any reachable user-controlled addresses
- Exploit idea: target function-call-key lifecycle state if the helper participates in it.
- Invariant to test: core balance, nonce, code, storage-generation, and token-registration state must stay internally consistent across every public execution path
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Cycle key addition and removal around crafted public flows and assert authorization state matches storage exactly. add integration tests that exercise the public path to the targeted helper, then assert balances, nonces, code bytes, storage keys, and mappings remain internally consistent
