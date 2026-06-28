# Q2170: exit_to_near_precompile_callback() amount scale split around ERC20 mint-based refund path in `setup_refund_on_error_input`

## Question
Can an attacker force ERC20 mint-based refund path in `setup_refund_on_error_input` to interpret the same amount under two different units, decimal conventions, or byte widths through `exit_to_near_precompile_callback()` on the Aurora engine contract, causing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `ERC20 mint-based refund path in `setup_refund_on_error_input``
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: attack amount scaling and numeric width at the named connector boundary.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Fuzz amount boundaries and compare the public amount with the actual burned, minted, transferred, or refunded amount. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
