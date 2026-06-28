# Q2135: exit_to_near_precompile_callback() private or owner split at transfer-near branch handling

## Question
Can an attacker exploit the 'private or owner' assumption around transfer-near branch handling through `exit_to_near_precompile_callback()` on the Aurora engine contract, so a public call mimics an internal path and mutates protected configuration or value-bearing state, leading to Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `transfer-near branch handling`
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: test whether the targeted branch really distinguishes private callbacks from external calls in all cases.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Call the method from both the intended internal path and a direct external path and compare authorization behavior before any mutation. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
