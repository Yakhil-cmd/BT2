## #Vulnerability found for this question.

### Title
Unvalidated `bcs::from_bytes(&func.args()[0]).unwrap()` panics on malformed entry-function argument bytes during transaction analysis/partitioning - (File: `types/src/transaction/analyzed_transaction.rs`)

### Summary
`AnalyzedTransaction::new` computes read/write hints for sharded block partitioning by calling `Transaction::get_read_write_hints`, which for `coin::transfer`, `aptos_account::transfer`, and `aptos_account::create_account` entry functions blindly decodes `func.args()[0]` as an `AccountAddress` using `bcs::from_bytes(...).unwrap()`. [1](#0-0)  Neither the argument count nor the BCS payload shape is validated before this call, and there is no type-checking of entry-function arguments against the target function's ABI at this stage.

### Finding Description
`get_read_write_hints` is invoked from `AnalyzedTransaction::new`, which is constructed via `From<SignatureVerifiedTransaction>`/`From<Transaction>` implementations. [2](#0-1)  This conversion runs after signature verification but before VM execution/type-checking, in the block-preparation/partitioning stage used by sharded execution (`BlockPreparationStage::process` in `execution/executor-benchmark/src/block_preparation.rs`) and by the experimental `ptx-executor` analyzer. [3](#0-2) [4](#0-3) 

An unprivileged user can submit a validly-signed `SignedTransaction` whose payload is an entry function call to `0x1::coin::transfer`, `0x1::aptos_account::transfer`, or `0x1::aptos_account::create_account`, with `args()[0]` populated with:
- Zero bytes (empty vec) — causing an immediate panic at `func.args()[0]` (index out of bounds) before even reaching `bcs::from_bytes`, or
- A truncated/invalid byte sequence that is not a valid 32-byte BCS-encoded `AccountAddress`, causing `bcs::from_bytes(...).unwrap()` to panic on `Err`.

Since the transaction only needs a valid signature (no on-chain state or gas/argument type validation occurs prior to this stage), any unprivileged party controlling their own signed transaction can trigger this panic on any node running the block-partitioner path.

### Impact Explanation
The panic occurs inside `Transaction::get_read_write_hints`, called synchronously during block preparation/partitioning (`BlockPreparationStage::process`, `ptx-executor` analyzer thread). A panic in this worker thread/stage crashes the process performing the partitioning, denying block preparation on that node until restarted. This is scoped to the partitioner/analysis stage — it does not by itself corrupt sender/receiver binding for committed transactions, but it does violate the invariant that malformed admission-relevant payload data must be gracefully rejected (`Result`) rather than causing a process panic.

### Likelihood Explanation
High — no privileged access, special key, or pre-existing approval is required. Any account holding a valid private key can craft a signed entry-function transaction with a truncated or empty first argument and submit it through normal transaction submission, reaching this analysis code as soon as it's picked up for sharded block partitioning.

### Recommendation
Replace the `.unwrap()` calls in `process_entry_function` with safe handling: validate `func.args()` length and use `bcs::from_bytes` with error propagation (e.g., returning `Result` from `get_read_write_hints`, or falling back to a wildcard/overestimated storage location such as `StorageLocation::WildCardStruct`/`WildCardTable` when decoding fails), so malformed arguments degrade the precision of the read/write-hint analysis instead of panicking.

### Proof of Concept
1. Construct a `SignedTransaction` with a valid signature whose payload is `EntryFunction::new(ModuleId::new(AccountAddress::ONE, "coin"), "transfer", vec![CoinType], vec![vec![0u8; 3], bcs::to_bytes(&1u64).unwrap()])` (i.e., `args()[0]` is 3 bytes instead of a valid 32-byte address).
2. Convert this transaction with `.into(): AnalyzedTransaction` (as done in `execution/executor-benchmark/src/block_preparation.rs` and block-partitioner tests, e.g. `create_signed_p2p_transaction` in `execution/block-partitioner/src/test_utils.rs`). [5](#0-4) 
3. Observe that `bcs::from_bytes(&func.args()[0]).unwrap()` panics instead of returning an error, crashing the calling thread/process rather than rejecting the malformed transaction gracefully.

### Citations

**File:** types/src/transaction/analyzed_transaction.rs (L142-158)
```rust
impl From<SignatureVerifiedTransaction> for AnalyzedTransaction {
    fn from(txn: SignatureVerifiedTransaction) -> Self {
        AnalyzedTransaction::new(txn)
    }
}

impl From<AnalyzedTransaction> for SignatureVerifiedTransaction {
    fn from(val: AnalyzedTransaction) -> Self {
        val.transaction
    }
}

impl From<Transaction> for AnalyzedTransaction {
    fn from(txn: Transaction) -> Self {
        AnalyzedTransaction::new(txn.into())
    }
}
```

**File:** types/src/transaction/analyzed_transaction.rs (L254-265)
```rust
                (AccountAddress::ONE, "coin", "transfer") => {
                    let receiver_address = bcs::from_bytes(&func.args()[0]).unwrap();
                    rw_set_for_coin_transfer(sender_address, receiver_address, true)
                },
                (AccountAddress::ONE, "aptos_account", "transfer") => {
                    let receiver_address = bcs::from_bytes(&func.args()[0]).unwrap();
                    rw_set_for_coin_transfer(sender_address, receiver_address, false)
                },
                (AccountAddress::ONE, "aptos_account", "create_account") => {
                    let receiver_address = bcs::from_bytes(&func.args()[0]).unwrap();
                    rw_set_for_create_account(sender_address, receiver_address)
                },
```

**File:** execution/executor-benchmark/src/block_preparation.rs (L98-111)
```rust
            Some(partitioner) => {
                NUM_TXNS.inc_with_by(&["partition"], sig_verified_txns.len() as u64);
                let analyzed_transactions =
                    sig_verified_txns.into_iter().map(|t| t.into()).collect();
                let timer = TIMER.timer_with(&["partition"]);
                let partitioned_txns =
                    partitioner.partition(analyzed_transactions, self.num_executor_shards);
                timer.stop_and_record();
                ExecutableBlock::new(
                    block_id,
                    ExecutableTransactions::Sharded(partitioned_txns),
                    vec![],
                )
            },
```

**File:** experimental/execution/ptx-executor/src/analyzer.rs (L22-27)
```rust
            loop {
                match work_rx.recv().expect("Channel closed.") {
                    Command::AnalyzeTransaction(txn) => {
                        let analyzed_txn = txn.into();
                        sorter.add_analyzed_transaction(analyzed_txn)
                    },
```

**File:** execution/block-partitioner/src/test_utils.rs (L85-93)
```rust
        let transaction_payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(AccountAddress::ONE, Identifier::new("coin").unwrap()),
            Identifier::new("transfer").unwrap(),
            vec![AptosCoinType::type_tag()],
            vec![
                bcs::to_bytes(&receiver.account_address).unwrap(),
                bcs::to_bytes(&1u64).unwrap(),
            ],
        ));
```
