# Q3080: XCC and promise-related precompiles recoverability gap after result retrieval in the promise-result precompile

## Question
Can an attacker make result retrieval in the promise-result precompile enter a failed state that neither cleanly reverts nor enables a safe refund or retry path, stranding funds or system capacity and causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine-precompiles/src/xcc.rs + promise_result.rs + prepaid_gas.rs + account_ids.rs + random.rs` -> `result retrieval in the promise-result precompile`
- Entrypoint: an EVM transaction that reaches Aurora precompile addresses for cross-contract calls, promise results, prepaid gas, account IDs, or randomness
- Attacker controls: EVM calldata to those precompile addresses, callback timing, promise graph shape, gas limit, and contract code that consumes the returned values
- Exploit idea: target failure states around the precompile that are neither final success nor clean revert.
- Invariant to test: environment and promise precompiles must expose accurate context and must not let user-controlled calls forge promise, identity, or gas state
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Enumerate recoverability after each distinct failure mode and assert there is always one safe compensation path. write EVM integration tests that call the relevant precompile addresses under different promise and gas contexts, then compare the returned values with expected runtime state
