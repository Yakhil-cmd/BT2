# Q2094: exit_to_near_precompile_callback() cross-asset mixup in private-call enforcement in the callback

## Question
Can an attacker use `exit_to_near_precompile_callback()` on the Aurora engine contract to make private-call enforcement in the callback associate the wrong token contract, metadata, or bridge account with the current action, so one asset is credited or debited as another and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `private-call enforcement in the callback`
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: abuse asset-identity assumptions at the targeted mapping or metadata step.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Exercise different token identities around the same flow and assert each path touches only its own balances and metadata. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
