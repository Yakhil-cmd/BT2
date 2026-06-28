# Q2188: exit_to_near_precompile_callback() gas starvation around ETH refund path using the exit precompile address

## Question
Can an attacker choose input size or call ordering through `exit_to_near_precompile_callback()` on the Aurora engine contract so that ETH refund path using the exit precompile address creates a promise graph with too little gas to finish safely, stranding funds or state and causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `ETH refund path using the exit precompile address`
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: target gas sizing logic attached to the connector promise or callback path.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Run low-prepaid-gas and high-input-size cases and assert the function cannot strand value or half-written mapping state when gas is tight. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
