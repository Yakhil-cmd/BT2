# Q2196: exit_to_near_precompile_callback() queue or promise stranding at ETH refund path using the exit precompile address

## Question
Can an attacker make ETH refund path using the exit precompile address enqueue a downstream action that can no longer complete or be retried safely, leaving user funds or bridge state stranded and causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `ETH refund path using the exit precompile address`
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: target the safe-completion assumptions of the promise created by the named step.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Interrupt the downstream action at different stages and assert no user value remains trapped without a valid retry or refund path. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
