# Q3020: native exit precompiles recoverability gap after coupling between native exit logs and `exit_to_near_precompile_callback`

## Question
Can an attacker make coupling between native exit logs and `exit_to_near_precompile_callback` enter a failed state that neither cleanly reverts nor enables a safe refund or retry path, stranding funds or system capacity and causing Permanent freezing of funds?

## Target
- File/function: `engine-precompiles/src/native.rs + engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback` -> `coupling between native exit logs and `exit_to_near_precompile_callback``
- Entrypoint: an EVM transaction submitted through `submit()`, `submit_with_args()`, `call()`, or `deploy_code()` that invokes the exit-to-NEAR or exit-to-Ethereum precompile
- Attacker controls: EVM calldata to the exit precompile, recipient bytes, amount, static-call context, repeated invocation timing, and revert behavior in the surrounding EVM call
- Exploit idea: target failure states around the precompile that are neither final success nor clean revert.
- Invariant to test: exit precompiles must burn, escrow, log, and callback exactly once for the intended asset and recipient
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Enumerate recoverability after each distinct failure mode and assert there is always one safe compensation path. write integration tests that invoke the native exit precompiles from EVM code with crafted recipient and amount values, then inspect logs, refunds, and balances
