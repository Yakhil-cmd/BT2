# Q2123: exit_to_near_precompile_callback() partial burn or refund at transfer-near branch handling

## Question
Can an attacker force transfer-near branch handling into a path where value is burned, escrowed, or promised before the success condition is finalized, then reclaim or replay value so the protocol loses funds and suffers Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `transfer-near branch handling`
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: attack ordering between burn/escrow and final success acknowledgement at the named step.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Instrument the failing downstream branch and assert burned or escrowed value is either fully restored or never consumed. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
