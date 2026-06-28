# Q2219: exit_to_near_precompile_callback() silo bypass through amount decoding from `RefundCallArgs`

## Question
Can an attacker use `exit_to_near_precompile_callback()` on the Aurora engine contract so that amount decoding from `RefundCallArgs` reaches token receive, submit, deploy, or mirror behavior that silo mode was supposed to block, resulting in Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `amount decoding from `RefundCallArgs``
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: find a public path around the targeted silo-related check.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Enable silo restrictions in state and verify every alternate public path still rejects the same blocked action. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
