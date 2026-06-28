# Q2083: exit_to_near_precompile_callback() partial burn or refund at private-call enforcement in the callback

## Question
Can an attacker force private-call enforcement in the callback into a path where value is burned, escrowed, or promised before the success condition is finalized, then reclaim or replay value so the protocol loses funds and suffers Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `private-call enforcement in the callback`
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: attack ordering between burn/escrow and final success acknowledgement at the named step.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Instrument the failing downstream branch and assert burned or escrowed value is either fully restored or never consumed. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
