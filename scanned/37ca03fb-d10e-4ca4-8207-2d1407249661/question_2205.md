# Q2205: exit_to_near_precompile_callback() promise shape confusion in amount decoding from `RefundCallArgs`

## Question
Can an attacker make amount decoding from `RefundCallArgs` observe an unexpected promise count, result index, or result type through `exit_to_near_precompile_callback()` on the Aurora engine contract, so the wrong branch mints, refunds, or registers state and leads to Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `amount decoding from `RefundCallArgs``
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: target assumptions about promise shape and result indexing inside the named connector step.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Mock or simulate alternate promise-result layouts and assert the function rejects every malformed layout before mutating value-bearing state. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
