# Q2186: exit_to_near_precompile_callback() duplicate registration through ETH refund path using the exit precompile address

## Question
Can an attacker use `exit_to_near_precompile_callback()` on the Aurora engine contract so that ETH refund path using the exit precompile address registers the same asset, account, or mapping twice under inconsistent metadata or addresses, breaking canonical mapping invariants and causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `ETH refund path using the exit precompile address`
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: create a duplicate or conflicting registration state around the targeted helper.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Attempt repeated registration and mixed metadata paths, then assert the canonical mapping stays one-to-one and balances remain intact. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
