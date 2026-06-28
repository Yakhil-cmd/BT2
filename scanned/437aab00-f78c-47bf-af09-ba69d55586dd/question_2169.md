# Q2169: exit_to_near_precompile_callback() recipient mismatch in ERC20 mint-based refund path in `setup_refund_on_error_input`

## Question
Can an attacker make ERC20 mint-based refund path in `setup_refund_on_error_input` route value to a different recipient than the one visible at the public entrypoint, via encoding, truncation, or mapping confusion, causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `ERC20 mint-based refund path in `setup_refund_on_error_input``
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: exploit a mismatch between public recipient intent and downstream recipient bytes or addresses.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Use crafted recipient values and compare the entrypoint-visible recipient with the recipient encoded in downstream calls or minted balances. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
