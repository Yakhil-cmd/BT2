# Q1009: EIP-7702 parsing call-create ambiguity near sender recovery in `sender()`

## Question
Can an attacker make sender recovery in `sender()` misclassify a transaction as a call when it should be a create, or vice versa, through `submit()` / `submit_with_args()` with an EIP-7702 transaction, so the wrong path consumes value or updates state and causes Theft of gas?

## Target
- File/function: `engine-transactions/src/eip_7702.rs` -> `sender recovery in `sender()``
- Entrypoint: `submit()` / `submit_with_args()` with an EIP-7702 transaction
- Attacker controls: typed transaction bytes, authorization list entries, calldata, fees, signature values, and relayer timing
- Exploit idea: target transaction fields that decide create-versus-call routing around the named subtarget.
- Invariant to test: EIP-7702 authorization and delegated-account handling must not bypass sender, code, nonce, or fee invariants
- Expected Immunefi impact: Theft of gas
- Fast validation: Exercise both empty-recipient and non-empty-recipient variants with identical payloads and assert only the intended route mutates code and balances. add tests that vary authorization-list content and sender code state, then assert `RejectCallerWithCode`, nonce, fees, and execution all stay aligned
