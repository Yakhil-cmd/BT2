# Q2164: exit_to_near_precompile_callback() callback spoof around ERC20 mint-based refund path in `setup_refund_on_error_input`

## Question
Can an attacker directly invoke or spoof the async context expected by ERC20 mint-based refund path in `setup_refund_on_error_input` through `exit_to_near_precompile_callback()` on the Aurora engine contract so a callback-only step runs with attacker-controlled bytes and causes Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::exit_to_near_precompile_callback -> engine/src/engine.rs::refund_on_error` -> `ERC20 mint-based refund path in `setup_refund_on_error_input``
- Entrypoint: `exit_to_near_precompile_callback()` on the Aurora engine contract
- Attacker controls: direct callback invocation attempts, borsh `ExitToNearPrecompileCallbackArgs`, amount bytes, transfer/refund option layout, and promise timing
- Exploit idea: treat the targeted function as if an attacker can call it out of context and check whether private-call or promise-result assumptions fully hold.
- Invariant to test: exit callbacks must either finalize one withdrawal or perform one correct refund, never both and never neither
- Expected Immunefi impact: Insolvency
- Fast validation: Call the callback entry directly from tests with crafted input and compare behavior to the legitimate promise path. write callback-focused integration tests that manipulate `promise_results_count`, refund payloads, and transfer payloads, then assert supply and balances stay correct
