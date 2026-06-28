# Q1508: engine accounting and storage rollback gap after ERC-20 registration in `register_token`

## Question
Can an attacker make a later stage fail after ERC-20 registration in `register_token` has already written core state, leaving a half-committed state transition that can be exploited for Insolvency?

## Target
- File/function: `engine/src/engine.rs + engine/src/accounting.rs + engine/src/state.rs` -> `ERC-20 registration in `register_token``
- Entrypoint: unprivileged `submit()`, `submit_with_args()`, `call()`, `deploy_code()`, connector methods, and precompile-triggered flows that reach core state updates
- Attacker controls: public transaction calldata, deployment input, transfer values, storage keys, bridge amounts, refund timing, and any reachable user-controlled addresses
- Exploit idea: force failure immediately after the targeted helper executes.
- Invariant to test: core balance, nonce, code, storage-generation, and token-registration state must stay internally consistent across every public execution path
- Expected Immunefi impact: Insolvency
- Fast validation: Inject a fault after the helper and assert every earlier state write is rolled back or safely compensated. add integration tests that exercise the public path to the targeted helper, then assert balances, nonces, code bytes, storage keys, and mappings remain internally consistent
