# Q2091: exit_to_near_precompile_callback() idempotence break at private-call enforcement in the callback

## Question
Can an attacker repeat the exact same public request through `exit_to_near_precompile_callback()` on the Aurora engine contract and make private-call enforcement in the callback treat it as fresh instead of already-consumed state, leading to Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `private-call enforcement in the callback`
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: look for missing idempotence or replay resistance at the targeted connector step.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Replay the same request and assert supply, storage registration, and mappings do not move on the second attempt. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
