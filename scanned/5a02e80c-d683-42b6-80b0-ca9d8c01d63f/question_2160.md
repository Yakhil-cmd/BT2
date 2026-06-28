# Q2160: exit_to_near_precompile_callback() resource exhaustion seeded by refund branch dispatch into `refund_on_error`

## Question
Can an attacker use `exit_to_near_precompile_callback()` on the Aurora engine contract so that refund branch dispatch into `refund_on_error` keeps creating state, promises, or registrations that the protocol must later pay to maintain, eventually causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `refund branch dispatch into `refund_on_error``
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: look for unbounded public resource creation rooted in the targeted connector step.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Run a high-count local sequence and measure whether protocol-held storage, registration state, or required connector balance grows without safe user-paid bounds. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
