# Q1295: deploy_code() multi-tx amplification through deployment input forwarding into `deploy_code_with_input`

## Question
Can an attacker batch or sequence many small transactions through `deploy_code()` on the Aurora engine contract so that deployment input forwarding into `deploy_code_with_input` applies a rounding, caching, or accounting shortcut that compounds into Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::deploy_code -> engine/src/engine.rs::deploy_code_with_input / deploy_code` -> `deployment input forwarding into `deploy_code_with_input``
- Entrypoint: `deploy_code()` on the Aurora engine contract
- Attacker controls: deployment bytecode, constructor input, repeated deployment timing, and any address constraints reachable through the entry path
- Exploit idea: amplify a per-call discrepancy at the subtarget across many user-controlled transactions.
- Invariant to test: contract deployment must charge and commit exactly once, derive the correct address, and never leave half-deployed state behind
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Run a high-count local sequence with tiny value and gas variations, then compare cumulative balances and fees against expected totals. write a Rust integration test that deploys crafted bytecode through `deploy_code()`, then checks address derivation, code storage, logs, balances, and revert handling
