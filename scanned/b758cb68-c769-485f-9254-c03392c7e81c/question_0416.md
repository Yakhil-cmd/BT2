# Q416: legacy Ethereum transaction parsing zero-address edge in call-versus-create routing when `to` is empty

## Question
Can an attacker hit a zero-address or empty-field edge through `submit()` / `submit_with_args()` with a legacy signed Ethereum transaction so that call-versus-create routing when `to` is empty routes the transaction differently from the rest of the engine and causes Temporary freezing of funds?

## Target
- File/function: `engine-transactions/src/legacy.rs` -> `call-versus-create routing when `to` is empty`
- Entrypoint: `submit()` / `submit_with_args()` with a legacy signed Ethereum transaction
- Attacker controls: legacy RLP fields including nonce, gas price, gas limit, `to`, value, calldata, signature values, and cross-chain replay timing
- Exploit idea: target the exact empty or zero-valued branch controlled by the subtarget.
- Invariant to test: legacy transaction parsing must produce one unambiguous sender, one gas obligation, and one execution intent
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Test empty recipient, zero sender-derived branch, and zero-value variants and assert route selection and state updates stay canonical. add parser and integration tests that mutate one legacy field at a time, then assert the same bytes cannot lead to divergent sender, fee, or execution outcomes
