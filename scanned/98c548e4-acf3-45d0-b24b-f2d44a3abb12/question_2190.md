# Q2190: exit_to_near_precompile_callback() amount scale split around ETH refund path using the exit precompile address

## Question
Can an attacker force ETH refund path using the exit precompile address to interpret the same amount under two different units, decimal conventions, or byte widths through `exit_to_near_precompile_callback()` on the Aurora engine contract, causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `ETH refund path using the exit precompile address`
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: attack amount scaling and numeric width at the named connector boundary.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Fuzz amount boundaries and compare the public amount with the actual burned, minted, transferred, or refunded amount. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
