# Q476: legacy Ethereum transaction parsing zero-address edge in legacy-to-normalized conversion consumed by `submit_with_alt_modexp`

## Question
Can an attacker hit a zero-address or empty-field edge through `submit()` / `submit_with_args()` with a legacy signed Ethereum transaction so that legacy-to-normalized conversion consumed by `submit_with_alt_modexp` routes the transaction differently from the rest of the engine and causes Theft of gas?

## Target
- File/function: `engine-transactions/src/legacy.rs` -> `legacy-to-normalized conversion consumed by `submit_with_alt_modexp``
- Entrypoint: `submit()` / `submit_with_args()` with a legacy signed Ethereum transaction
- Attacker controls: legacy RLP fields including nonce, gas price, gas limit, `to`, value, calldata, signature values, and cross-chain replay timing
- Exploit idea: target the exact empty or zero-valued branch controlled by the subtarget.
- Invariant to test: legacy transaction parsing must produce one unambiguous sender, one gas obligation, and one execution intent
- Expected Immunefi impact: Theft of gas
- Fast validation: Test empty recipient, zero sender-derived branch, and zero-value variants and assert route selection and state updates stay canonical. add parser and integration tests that mutate one legacy field at a time, then assert the same bytes cannot lead to divergent sender, fee, or execution outcomes
