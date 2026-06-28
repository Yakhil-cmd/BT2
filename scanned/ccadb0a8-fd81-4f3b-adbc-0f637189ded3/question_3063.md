# Q3063: XCC and promise-related precompiles static-context side effect in result retrieval in the promise-result precompile

## Question
Can an attacker reach result retrieval in the promise-result precompile via a static call through an EVM transaction that reaches Aurora precompile addresses for cross-contract calls, promise results, prepaid gas, account IDs, or randomness and still trigger stateful behavior, logs, or async promises that should have been forbidden, causing Smart contract unable to operate due to lack of funds?

## Target
- File/function: `engine-precompiles/src/xcc.rs + promise_result.rs + prepaid_gas.rs + account_ids.rs + random.rs` -> `result retrieval in the promise-result precompile`
- Entrypoint: an EVM transaction that reaches Aurora precompile addresses for cross-contract calls, promise results, prepaid gas, account IDs, or randomness
- Attacker controls: EVM calldata to those precompile addresses, callback timing, promise graph shape, gas limit, and contract code that consumes the returned values
- Exploit idea: check whether the targeted precompile fully respects static-call restrictions.
- Invariant to test: environment and promise precompiles must expose accurate context and must not let user-controlled calls forge promise, identity, or gas state
- Expected Immunefi impact: Smart contract unable to operate due to lack of funds
- Fast validation: Invoke the precompile from a Solidity/EVM static context and assert no state, log, or promise side effect occurs. write EVM integration tests that call the relevant precompile addresses under different promise and gas contexts, then compare the returned values with expected runtime state
