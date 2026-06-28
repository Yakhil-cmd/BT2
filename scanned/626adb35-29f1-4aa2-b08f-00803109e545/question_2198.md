# Q2198: exit_to_near_precompile_callback() revert/success split after ETH refund path using the exit precompile address

## Question
Can an attacker make ETH refund path using the exit precompile address treat a downstream revert as success, or a downstream success as failure, so mint, refund, or registration logic goes down the wrong branch and leads to Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `ETH refund path using the exit precompile address`
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: attack success detection and branch selection around the targeted callback or promise result.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Simulate both success and failure promise outcomes and assert the chosen branch matches the real downstream result every time. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
