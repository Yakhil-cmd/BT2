After an extensive search across the gateway validation, blockifier pre-execution, transaction conversion, bouncer accounting, gas counter initialization, nonce handling, fee/resource bounds, compiled class hash validation, and proof-facts parsing paths, I was unable to identify a production-reachable root cause that matches the required impact scope.

Specifically:

- **Nonce accounting**: `handle_nonce` in `account_transaction.rs` and `validate_nonce` in `stateful_transaction_validator.rs` both read the on-chain nonce before comparing and incrementing; there is no initialization-vs-accumulation split analogous to the ERC20 `_totalSupply` pattern.
- **Bouncer weights**: `Bouncer::new` initializes `accumulated_weights` via `TxWeights::empty()` (all zeros); the non-zero `BouncerWeights::default()` values are used only as *capacity limits*, not as starting accumulated weights.
- **Gas counter**: `GasCounter::new` sets `spent_gas = GasAmount(0)` and `remaining_gas = initial_gas`; the initial gas is derived directly from the transaction's `l2_gas.max_amount` or the protocol default, with no phantom pre-charged amount.
- **`receipt_l2_gas` in `run_non_revertible`**: The literal `GasAmount(0)` passed as the last argument to `TransactionReceipt::from_account_tx` is suspicious, but without the full `TransactionRecei