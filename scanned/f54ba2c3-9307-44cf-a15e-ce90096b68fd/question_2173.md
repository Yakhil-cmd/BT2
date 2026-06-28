# Q2173: exit_to_near_precompile_callback() rollback gap after ERC20 mint-based refund path in `setup_refund_on_error_input`

## Question
Can an attacker make ERC20 mint-based refund path in `setup_refund_on_error_input` mutate state or emit a promise before a later failing step aborts the public call, leaving a rollback gap that can be exploited for Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `ERC20 mint-based refund path in `setup_refund_on_error_input``
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: force a failure immediately after the named connector mutation or promise creation.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Cause the downstream step to fail and verify all earlier state, supply, and mapping changes are either rolled back or safely compensated. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
