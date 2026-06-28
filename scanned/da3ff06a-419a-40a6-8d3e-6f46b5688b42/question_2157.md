# Q2157: exit_to_near_precompile_callback() connector target confusion in refund branch dispatch into `refund_on_error`

## Question
Can an attacker route refund branch dispatch into `refund_on_error` toward the wrong connector account or downstream method through `exit_to_near_precompile_callback()` on the Aurora engine contract, so a valid-looking request lands in the wrong contract context and causes Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `refund branch dispatch into `refund_on_error``
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: abuse connector account selection and method-name routing near the targeted helper.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Insolvency
- Fast validation: Inspect the generated promise target account and method for crafted inputs and assert they always match the intended operation. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
