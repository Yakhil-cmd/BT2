# Q2212: exit_to_near_precompile_callback() mapping collision around amount decoding from `RefundCallArgs`

## Question
Can an attacker choose inputs through `exit_to_near_precompile_callback()` on the Aurora engine contract so that amount decoding from `RefundCallArgs` collides two distinct users, assets, or registrations into one storage key or one effective route, causing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `amount decoding from `RefundCallArgs``
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: target the storage key or mapping derivation consumed by the named step.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Search for colliding identifiers under fuzzed account and asset inputs and assert the contract always preserves one-to-one mappings. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
