# Q1515: engine accounting and storage supply/registration split around ERC-20 registration in `register_token`

## Question
Can an attacker use unprivileged `submit()`, `submit_with_args()`, `call()`, `deploy_code()`, connector methods, and precompile-triggered flows that reach core state updates so that ERC-20 registration in `register_token` updates token backing or registration state without the matching supply semantics, causing Permanent freezing of funds?

## Target
- File/function: `engine/src/engine.rs + engine/src/accounting.rs + engine/src/state.rs` -> `ERC-20 registration in `register_token``
- Entrypoint: unprivileged `submit()`, `submit_with_args()`, `call()`, `deploy_code()`, connector methods, and precompile-triggered flows that reach core state updates
- Attacker controls: public transaction calldata, deployment input, transfer values, storage keys, bridge amounts, refund timing, and any reachable user-controlled addresses
- Exploit idea: desynchronize token registration from balance or supply state at the helper.
- Invariant to test: core balance, nonce, code, storage-generation, and token-registration state must stay internally consistent across every public execution path
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Compare registration changes with resulting supply and backing balances after each crafted flow. add integration tests that exercise the public path to the targeted helper, then assert balances, nonces, code bytes, storage keys, and mappings remain internally consistent
