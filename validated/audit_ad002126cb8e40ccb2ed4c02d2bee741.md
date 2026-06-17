After thorough analysis of the ZKsync OS codebase, I mapped the external report's vulnerability class — **inconsistent enforcement of access control/restriction checks across different code paths** — to the ZKsync OS transaction validation system.

**Key patterns investigated:**

1. **`TxValidator` applied to L2 but not L1 transactions** — `process_l2_transaction` calls `validator.begin_tx()` at [1](#0-0)  while `process_l1_transaction` never invokes the validator hook. This is explicitly tested and documented as intentional — L1 transactions cannot be invalidated without halting the chain. [2](#0-1) 

2. **Nonce incremented before nonce check, with simulation-mode skip** — In `zk/validation_impl.rs`, the nonce is unconditionally incremented at line 334 for any transaction with a nonce field, but the nonce

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/process_transaction.rs (L92-109)
```rust
        // Pre-execution validation hook for L2 transactions only
        let ctx = BeginTxContext {
            from: *transaction.from(),
            to: transaction.to(),
            value: *transaction.value(),
            calldata: transaction.calldata(),
            gas_limit: transaction.gas_limit(),
        };
        let pre_validation = validator.begin_tx(&ctx);

        if let Err(validation_err) = pre_validation {
            system_log!(
                system,
                "Tx rejected by validator during begin_tx: {:?}\n",
                validation_err
            );
            return Err(TxError::Validation(validation_err.into()));
        }
```

**File:** tests/instances/unit/src/validator/tx_validator_filtering.rs (L204-248)
```rust
#[test]
fn test_l1_transactions_are_not_filtered_by_validator() {
    let mut tester = TestingFramework::new();
    let wallet = tester.random_signer();
    let from = wallet.address();

    let withdrawal_to = address!("000000000000000000000000000000000000800a");
    let withdrawal_calldata =
        hex::decode("51cff8d9000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();

    tester = tester.with_balance(from, U256::from(10_000_000));

    let mk_l1_tx = |nonce: u64, value: u64| {
        L1TxBuilder::new()
            .from(from)
            .to(withdrawal_to)
            .gas_price(1000u128.into())
            .gas_limit(500_000u64.into())
            .value(U256::from(value))
            .input(withdrawal_calldata.clone().into())
            .nonce(nonce.into())
            .build()
            .into()
    };

    let tx0 = mk_l1_tx(0, 10);
    let tx1 = mk_l1_tx(1, 11);

    let mut tracer = NopTracer::default();
    let mut validator = LoggingTxValidator::new(true, false);

    let out = tester.execute_block_with_tracing(vec![tx0, tx1], &mut tracer, &mut validator);

    println!(
        "[TxValidator] totals: begin_calls={}, finish_calls={}",
        validator.begin_calls, validator.finish_calls
    );

    // L1 transactions should NOT be filtered by the validator
    // Validator.begin_tx() should never be called for L1 transactions
    assert_eq!(
        validator.begin_calls, 0,
        "L1 transactions should not trigger validator.begin_tx()"
    );
```
