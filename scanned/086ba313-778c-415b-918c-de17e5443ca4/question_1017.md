# Q1017: EIP-7702 parsing log filter mismatch after sender recovery in `sender()`

## Question
Can an attacker make sender recovery in `sender()` emit logs or promise markers that the engine filters differently from the committed state, letting external systems or callbacks act on the wrong interpretation and eventually causing Theft of gas?

## Target
- File/function: `engine-transactions/src/eip_7702.rs` -> `sender recovery in `sender()``
- Entrypoint: `submit()` / `submit_with_args()` with an EIP-7702 transaction
- Attacker controls: typed transaction bytes, authorization list entries, calldata, fees, signature values, and relayer timing
- Exploit idea: exploit disagreement between emitted logs/promise markers and committed value movement around the subtarget.
- Invariant to test: EIP-7702 authorization and delegated-account handling must not bypass sender, code, nonce, or fee invariants
- Expected Immunefi impact: Theft of gas
- Fast validation: Capture raw logs and filtered logs for crafted transactions and confirm they cannot imply value movement different from committed state. add tests that vary authorization-list content and sender code state, then assert `RejectCallerWithCode`, nonce, fees, and execution all stay aligned
