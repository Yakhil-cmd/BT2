# Q3114: XCC and promise-related precompiles hardfork selection gap affecting current-account derivation

## Question
Can an attacker rely on an EVM transaction that reaches Aurora precompile addresses for cross-contract calls, promise results, prepaid gas, account IDs, or randomness to select a hardfork-specific precompile behavior around current-account derivation that differs from the rest of the engine’s assumptions, causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine-precompiles/src/xcc.rs + promise_result.rs + prepaid_gas.rs + account_ids.rs + random.rs` -> `current-account derivation`
- Entrypoint: an EVM transaction that reaches Aurora precompile addresses for cross-contract calls, promise results, prepaid gas, account IDs, or randomness
- Attacker controls: EVM calldata to those precompile addresses, callback timing, promise graph shape, gas limit, and contract code that consumes the returned values
- Exploit idea: look for precompile-set construction mismatches across hardfork constructors or engine config.
- Invariant to test: environment and promise precompiles must expose accurate context and must not let user-controlled calls forge promise, identity, or gas state
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Instantiate the precompile set under the active config and verify the targeted behavior and address map match the engine’s execution assumptions. write EVM integration tests that call the relevant precompile addresses under different promise and gas contexts, then compare the returned values with expected runtime state
