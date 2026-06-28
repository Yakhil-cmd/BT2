# Q2199: exit_to_near_precompile_callback() silo bypass through ETH refund path using the exit precompile address

## Question
Can an attacker use `exit_to_near_precompile_callback()` on the Aurora engine contract so that ETH refund path using the exit precompile address reaches token receive, submit, deploy, or mirror behavior that silo mode was supposed to block, resulting in Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `ETH refund path using the exit precompile address`
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: find a public path around the targeted silo-related check.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Insolvency
- Fast validation: Enable silo restrictions in state and verify every alternate public path still rejects the same blocked action. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
