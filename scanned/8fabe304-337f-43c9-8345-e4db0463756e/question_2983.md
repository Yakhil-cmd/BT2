# Q2983: native exit precompiles static-context side effect in behavior under static-call context

## Question
Can an attacker reach behavior under static-call context via a static call through an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile and still trigger stateful behavior, logs, or async promises that should have been forbidden, causing Insolvency?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `behavior under static-call context`
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: check whether the targeted precompile fully respects static-call restrictions.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Insolvency
- Fast validation: Invoke the precompile from a Solidity/EVM static context and assert no state, log, or promise side effect occurs. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
