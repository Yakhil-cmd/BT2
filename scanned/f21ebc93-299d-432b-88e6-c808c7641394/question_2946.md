# Q2946: native exit precompiles callback coupling bug at burn-before-callback sequencing

## Question
Can an attacker invoke burn-before-callback sequencing so that the async or callback logic coupled to its output or logs observes inconsistent data, leading to duplicate payout, missed refund, or Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `burn-before-callback sequencing`
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: split the precompile’s immediate output from the callback or refund logic that later consumes it.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Capture the exact emitted logs/output and ensure every downstream callback consumes only one canonical interpretation. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
