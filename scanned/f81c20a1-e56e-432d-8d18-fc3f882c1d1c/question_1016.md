# Q1016: EIP-7702 parsing zero-address edge in sender recovery in `sender()`

## Question
Can an attacker hit a zero-address or empty-field edge through `submit()` / `submit_with_args()` with an EIP-7702 transaction so that sender recovery in `sender()` routes the transaction differently from the rest of the engine and causes Insolvency?

## Target
- File/function: `engine-transactions/src/eip_7702.rs` -> `sender recovery in `sender()``
- Entrypoint: `submit()` / `submit_with_args()` with an EIP-7702 transaction
- Attacker controls: typed transaction bytes, authorization list entries, calldata, fees, signature values, and relayer timing
- Exploit idea: target the exact empty or zero-valued branch controlled by the subtarget.
- Invariant to test: EIP-7702 authorization and delegated-account handling must not bypass sender, code, nonce, or fee invariants
- Expected Immunefi impact: Insolvency
- Fast validation: Test empty recipient, zero sender-derived branch, and zero-value variants and assert route selection and state updates stay canonical. add tests that vary authorization-list content and sender code state, then assert `RejectCallerWithCode`, nonce, fees, and execution all stay aligned
