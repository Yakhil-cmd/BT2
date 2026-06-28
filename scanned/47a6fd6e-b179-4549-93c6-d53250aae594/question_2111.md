# Q2111: exit_to_near_precompile_callback() idempotence break at single-promise-result enforcement

## Question
Can an attacker repeat the exact same public request through `exit_to_near_precompile_callback()` on the Aurora engine contract and make single-promise-result enforcement treat it as fresh instead of already-consumed state, leading to Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `single-promise-result enforcement`
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: look for missing idempotence or replay resistance at the targeted connector step.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Insolvency
- Fast validation: Replay the same request and assert supply, storage registration, and mappings do not move on the second attempt. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
