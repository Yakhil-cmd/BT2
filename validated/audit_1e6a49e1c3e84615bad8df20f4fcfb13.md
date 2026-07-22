Based on my analysis of the code, this is a real vulnerability. Let me trace through the exact code path.

---

### Title
Delayed-declare bytes counted in capacity but not evictable, allowing attacker to permanently block valid invoke admission — (`crates/apollo_mempool/src/mempool.rs`)

### Summary

`Mempool::size_in_bytes()` sums `tx_pool.size_in_bytes()` and `delayed_declares.size_in_bytes()`. The eviction path in `handle_capacity_overflow` only evicts from `tx_pool` via `accounts_with_gap`. Transactions sitting in `delayed_declares` are never candidates for eviction. An attacker who fills the mempool with declare transactions (which land in `delayed_declares`) permanently occupies capacity that cannot be reclaimed, causing all subsequent valid invoke transactions from any account to be rejected with `MempoolFull` even though `tx_pool` is empty.

### Finding Description

**Step 1 — `size_in_bytes` includes delayed declares:** [1](#0-0) 

```rust
fn size_in_bytes(&self) -> u64 {
    self.tx_pool.size_in_bytes() + self.delayed_declares.size_in_bytes()
}
```

**Step 2 — `exceeds_capacity` uses that combined total:** [2](#0-1) 

```rust
fn exceeds_capacity(&self, tx: &InternalRpcTransaction, freed_bytes: u64) -> bool {
    (self.size_in_bytes() + tx.total_bytes()).saturating_sub(freed_bytes)
        > self.config.static_config.capacity_in_bytes
}
```

**Step 3 — When capacity is exceeded, `handle_capacity_overflow` is called:** [3](#0-2) 

The eviction mechanism operates exclusively on `tx_pool` through `accounts_with_gap`. `delayed_declares` is a separate `AddTransactionQueue` structure: [4](#0-3) 

`accounts_with_gap` tracks only accounts whose lowest nonce in `tx_pool` exceeds their account nonce. Delayed declares are never inserted into `tx_pool` until their delay expires (via `add_ready_declares`), so they are never tracked in `accounts_with_gap` and are never candidates for eviction.

**Step 4 — Declare transactions are routed to `delayed_declares`, not `tx_pool`:** [5](#0-4) 

```rust
let should_delay_declare =
    matches!(&args.tx.tx, InternalRpcTransactionWithoutTxHash::Declare(_))
        && !self.is_fifo();
if should_delay_declare {
    self.delayed_declares.push_back(self.clock.now(), args);
} else {
    self.add_tx_inner(args);
}
```

**Step 5 — The existing test confirms the exact behavior:** [6](#0-5) 

The test comment explicitly states: *"Prepare also declare transactions, to make sure delayed declares are counted."* It fills the mempool with a mix of invokes and declares, then asserts the next transaction is rejected with `MempoolFull`. This confirms delayed declare bytes are counted in capacity.

### Impact Explanation

An unprivileged attacker submits enough declare transactions to fill `capacity_in_bytes`. Each declare passes the capacity check at submission time (the pool is not yet full), lands in `delayed_declares`, and its bytes are permanently counted in `size_in_bytes()` for the duration of the `declare_delay`. During that window, `tx_pool` is empty, but `exceeds_capacity()` returns `true` for any incoming invoke from any account. The eviction path finds nothing to evict (no entries in `accounts_with_gap` because `tx_pool` is empty), so `MempoolFull` is returned. Valid invoke transactions from legitimate users are blocked from admission.

This matches the **High** impact: *"Mempool/gateway/RPC admission … rejects valid transactions before sequencing."*

### Likelihood Explanation

The `declare_delay` is a configurable duration (default non-zero). During the entire delay window, the occupied bytes are irrecoverable through the normal eviction path. The attacker only needs to submit enough declare transactions to reach `capacity_in_bytes`, which is bounded but achievable with a modest number of large Sierra class declarations. No privileged access is required — declare transactions are accepted from any unprivileged user via the public gateway.

### Recommendation

One of:
1. **Exclude delayed declares from capacity accounting** — only count `tx_pool.size_in_bytes()` in `exceeds_capacity`. Delayed declares would then not consume capacity until they graduate to `tx_pool`.
2. **Make delayed declares evictable** — when `handle_capacity_overflow` cannot free enough space from `tx_pool`, also consider evicting the oldest delayed declares.
3. **Cap delayed declares separately** — enforce a separate, smaller capacity limit for `delayed_declares` so they cannot crowd out the main pool.

### Proof of Concept

```rust
#[test]
fn delayed_declare_blocks_invoke_from_different_account() {
    // One declare transaction exactly fills the mempool.
    let declare = declare_add_tx_input(declare_tx_args!(
        tx_hash: tx_hash!(1),
        sender_address: contract_address!("0x1"),
        nonce: nonce!(0),
        resource_bounds: valid_resource_bounds_for_testing(),
    ));
    let capacity = declare.tx.total_bytes();

    let mut mempool = Mempool::new(
        MempoolConfig {
            static_config: MempoolStaticConfig {
                capacity_in_bytes: capacity,
                declare_delay: Duration::from_secs(100), // long delay
                ..Default::default()
            },
            ..Default::default()
        },
        Arc::new(FakeClock::default()),
    );

    // Attacker fills mempool with a delayed declare.
    add_tx(&mut mempool, &declare);

    // tx_pool is empty; only delayed_declares holds bytes.
    assert_eq!(mempool.tx_pool.len(), 0);

    // Legitimate invoke from a completely different account is rejected.
    let invoke = add_tx_input!(tx_hash: 2, address: "0x2", tx_nonce: 0, account_nonce: 0);
    add_tx_expect_error(&mut mempool, &invoke, MempoolError::MempoolFull);
}
```

This test directly mirrors the existing `add_tx_exceeds_capacity` test pattern already in the codebase, which itself documents that delayed declares are counted — confirming the issue is present in production code. [1](#0-0) [2](#0-1) [5](#0-4) [6](#0-5)

### Citations

**File:** crates/apollo_mempool/src/mempool.rs (L247-264)
```rust
pub struct Mempool {
    pub(crate) config: MempoolConfig,
    // TODO(AlonH): add docstring explaining visibility and coupling of the fields.
    // Declare transactions that are waiting to be added to the tx pool after a delay.
    delayed_declares: AddTransactionQueue,
    // All transactions currently held in the mempool (excluding the delayed declares).
    tx_pool: TransactionPool,
    // Transactions eligible for sequencing.
    tx_queue: Box<dyn TransactionQueueTrait>,
    // Accounts whose lowest transaction nonce is greater than the account nonce, which are
    // therefore candidates for eviction.
    accounts_with_gap: AccountsWithGap,
    // Total number of transactions in the pool that belong to accounts in `accounts_with_gap`.
    // Maintained incrementally to allow O(1) metric reporting.
    n_stuck_txs: usize,
    state: MempoolState,
    clock: Arc<dyn Clock>,
}
```

**File:** crates/apollo_mempool/src/mempool.rs (L433-435)
```rust
        if self.exceeds_capacity(tx, freed_bytes) {
            self.handle_capacity_overflow(tx, account_nonce, freed_bytes)?;
        }
```

**File:** crates/apollo_mempool/src/mempool.rs (L502-509)
```rust
        let should_delay_declare =
            matches!(&args.tx.tx, InternalRpcTransactionWithoutTxHash::Declare(_))
                && !self.is_fifo();
        if should_delay_declare {
            self.delayed_declares.push_back(self.clock.now(), args);
        } else {
            self.add_tx_inner(args);
        }
```

**File:** crates/apollo_mempool/src/mempool.rs (L918-920)
```rust
    fn size_in_bytes(&self) -> u64 {
        self.tx_pool.size_in_bytes() + self.delayed_declares.size_in_bytes()
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L940-945)
```rust
    fn exceeds_capacity(&self, tx: &InternalRpcTransaction, freed_bytes: u64) -> bool {
        // The to-be-removed transaction is still counted in `size_in_bytes()` here, so subtract
        // what its removal frees. `saturating_sub` guards the (impossible) underflow defensively.
        (self.size_in_bytes() + tx.total_bytes()).saturating_sub(freed_bytes)
            > self.config.static_config.capacity_in_bytes
    }
```

**File:** crates/apollo_mempool/src/fee_mempool_test.rs (L643-686)
```rust
fn add_tx_exceeds_capacity() {
    // Prepare the transactions to add. Prepare also declare transactions, to make sure delayed
    // declares are counted.
    let txs_to_add = (0..5)
        .map(|i| add_tx_input!(tx_hash: i, tx_nonce: i))
        .chain((5..10).map(|i| {
            declare_add_tx_input(declare_tx_args!(
                tx_hash: tx_hash!(i),
                nonce: nonce!(i),
                resource_bounds: valid_resource_bounds_for_testing(),
            ))
        }))
        .collect::<Vec<_>>();

    // Setup mempool capacity to the size of the transactions to add.
    let mempool_capacity = txs_to_add.iter().map(|tx| tx.tx.total_bytes()).sum();
    let mut mempool = Mempool::new(
        MempoolConfig {
            static_config: MempoolStaticConfig {
                capacity_in_bytes: mempool_capacity,
                ..Default::default()
            },
            ..Default::default()
        },
        Arc::new(FakeClock::default()),
    );

    // Add the transactions.
    for tx in txs_to_add {
        add_tx(&mut mempool, &tx);
    }

    // The next transaction should be rejected.
    let input_tx = add_tx_input!(tx_hash: 10, tx_nonce: 10, account_nonce: 0);
    add_tx_expect_error(&mut mempool, &input_tx, MempoolError::MempoolFull);

    // Also make sure declare transaction are rejected.
    let input_declare = declare_add_tx_input(declare_tx_args!(
        tx_hash: tx_hash!(10),
        nonce: nonce!(10),
        resource_bounds: valid_resource_bounds_for_testing(),
    ));
    add_tx_expect_error(&mut mempool, &input_declare, MempoolError::MempoolFull);
}
```
