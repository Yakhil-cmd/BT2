# Q2156: exit_to_near_precompile_callback() queue or promise stranding at refund branch dispatch into `refund_on_error`

## Question
Can an attacker make refund branch dispatch into `refund_on_error` enqueue a downstream action that can no longer complete or be retried safely, leaving user funds or bridge state stranded and causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `refund branch dispatch into `refund_on_error``
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: target the safe-completion assumptions of the promise created by the named step.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Interrupt the downstream action at different stages and assert no user value remains trapped without a valid retry or refund path. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
