# Q3159: XCC and promise-related precompiles supply coupling bug at random-seed exposure to EVM code

## Question
Can an attacker invoke random-seed exposure to EVM code so that token supply, bridge supply, or escrow supply coupled to the precompile drifts from the actual burned or minted amount, causing Smart contract unable to operate due to lack of funds?

## Target
- File/function: `engine-precompiles/src/xcc.rs + promise_result.rs + prepaid_gas.rs + account_ids.rs + random.rs` -> `random-seed exposure to EVM code`
- Entrypoint: an EVM transaction that reaches Aurora precompile addresses for cross-contract calls, promise results, prepaid gas, account IDs, or randomness
- Attacker controls: EVM calldata to those precompile addresses, callback timing, promise graph shape, gas limit, and contract code that consumes the returned values
- Exploit idea: check how the targeted precompile’s output is coupled to supply-moving code.
- Invariant to test: environment and promise precompiles must expose accurate context and must not let user-controlled calls forge promise, identity, or gas state
- Expected Immunefi impact: Smart contract unable to operate due to lack of funds
- Fast validation: Track total supply, escrowed balances, and recipient balances before and after the crafted call sequence. write EVM integration tests that call the relevant precompile addresses under different promise and gas contexts, then compare the returned values with expected runtime state
