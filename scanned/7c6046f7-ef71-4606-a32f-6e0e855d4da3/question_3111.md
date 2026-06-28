# Q3111: XCC and promise-related precompiles address aliasing around current-account derivation

## Question
Can an attacker reach current-account derivation through an aliased or unexpected precompile address under an EVM transaction that reaches Aurora precompile addresses for cross-contract calls, promise results, prepaid gas, account IDs, or randomness, bypassing the address-specific assumptions of surrounding code and causing Temporary freezing of funds?

## Target
- File/function: `engine-precompiles/src/xcc.rs + promise_result.rs + prepaid_gas.rs + account_ids.rs + random.rs` -> `current-account derivation`
- Entrypoint: an EVM transaction that reaches Aurora precompile addresses for cross-contract calls, promise results, prepaid gas, account IDs, or randomness
- Attacker controls: EVM calldata to those precompile addresses, callback timing, promise graph shape, gas limit, and contract code that consumes the returned values
- Exploit idea: look for address-level confusion in the precompile set or downstream consumers.
- Invariant to test: environment and promise precompiles must expose accurate context and must not let user-controlled calls forge promise, identity, or gas state
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Probe all configured precompile addresses and confirm only the intended address family reaches the targeted logic. write EVM integration tests that call the relevant precompile addresses under different promise and gas contexts, then compare the returned values with expected runtime state
