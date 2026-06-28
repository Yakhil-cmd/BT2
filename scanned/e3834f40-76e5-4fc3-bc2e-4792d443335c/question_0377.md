# Q377: legacy Ethereum transaction parsing log filter mismatch after ECDSA sender recovery in `sender()`

## Question
Can an attacker make ECDSA sender recovery in `sender()` emit logs or promise markers that the engine filters differently from the committed state, letting external systems or callbacks act on the wrong interpretation and eventually causing Theft of gas?

## Target
- File/function: `engine-transactions/src/legacy.rs` -> `ECDSA sender recovery in `sender()``
- Entrypoint: `submit()` / `submit_with_args()` with a legacy signed Ethereum transaction
- Attacker controls: legacy RLP fields including nonce, gas price, gas limit, `to`, value, calldata, signature values, and cross-chain replay timing
- Exploit idea: exploit disagreement between emitted logs/promise markers and committed value movement around the subtarget.
- Invariant to test: legacy transaction parsing must produce one unambiguous sender, one gas obligation, and one execution intent
- Expected Immunefi impact: Theft of gas
- Fast validation: Capture raw logs and filtered logs for crafted transactions and confirm they cannot imply value movement different from committed state. add parser and integration tests that mutate one legacy field at a time, then assert the same bytes cannot lead to divergent sender, fee, or execution outcomes
