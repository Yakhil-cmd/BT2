# Q796: EIP-1559 parsing zero-address edge in normalization into `submit_with_alt_modexp`

## Question
Can an attacker hit a zero-address or empty-field edge through `submit()` / `submit_with_args()` with an EIP-1559 transaction so that normalization into `submit_with_alt_modexp` routes the transaction differently from the rest of the engine and causes Theft of gas?

## Target
- File/function: `engine-transactions/src/eip_1559.rs` -> `normalization into `submit_with_alt_modexp``
- Entrypoint: `submit()` / `submit_with_args()` with an EIP-1559 transaction
- Attacker controls: EIP-1559 fee fields, gas limit, access list, calldata, value, signature values, and relayer choice
- Exploit idea: target the exact empty or zero-valued branch controlled by the subtarget.
- Invariant to test: EIP-1559 fee semantics must remain aligned between parsing, gas charging, refunding, and execution
- Expected Immunefi impact: Theft of gas
- Fast validation: Test empty recipient, zero sender-derived branch, and zero-value variants and assert route selection and state updates stay canonical. add integration tests that target EIP-1559 fee extremes and assert `charge_gas` and `refund_unused_gas` preserve the expected sender and relayer balances
