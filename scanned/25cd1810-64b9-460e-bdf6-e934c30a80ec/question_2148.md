# Q2148: exit_to_near_precompile_callback() gas starvation around refund branch dispatch into `refund_on_error`

## Question
Can an attacker choose input size or call ordering through `exit_to_near_precompile_callback()` on the Aurora engine contract so that refund branch dispatch into `refund_on_error` creates a promise graph with too little gas to finish safely, stranding funds or state and causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `refund branch dispatch into `refund_on_error``
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: target gas sizing logic attached to the connector promise or callback path.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Run low-prepaid-gas and high-input-size cases and assert the function cannot strand value or half-written mapping state when gas is tight. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
