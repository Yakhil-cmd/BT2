The vulnerability claim is **valid**. Here is the analysis:

### Title
Delayed-Declare Capacity Squatting Blocks Legitimate Transaction Admission - (`crates/apollo_mempool/src/mempool.rs`)

### Summary
`Mempool::size_in_bytes()` aggregates both `tx_pool` and `delayed_declares` byte counts. An unprivileged attacker can flood `delayed_declares` with declare transactions (each individually admitted under capacity), exhausting the shared byte budget before the declare delay expires. Subsequent legitimate invoke transactions are then rejected with `MempoolError::MempoolFull` because the only eviction path (`try_make_space`) exclusively targets `tx_pool` gap-account entries and cannot reclaim bytes held in `delayed_declares`.

### Finding Description

**Step 1 — Shared capacity accounting.**
`size_in_bytes()` sums both sub-stores:

```rust
fn size_in_bytes(&self) -> u64 {
    self.tx_pool.size_in_bytes() + self.delayed_declares.size_in_bytes()
}
``` [1](#0-0) 

`exceeds_capacity()` uses this combined figure directly against `capacity_in_bytes`:

```rust
(self.size_in_bytes() + tx.total_bytes()).saturating_sub(freed_bytes)
    > self.config.static_config.capacity_in_bytes
``` [2](#0-1) 

**Step 2 — Attacker fills `delayed_declares` incrementally.**
Each `add_tx()` call for a declare transaction first calls `add_ready_declares()` (line 483), but that only drains entries whose `declare_delay` has already elapsed. While the delay is still active, every attacker-submitted declare passes the capacity check (capacity not yet exceeded) and is appended to `delayed_declares`:

```rust
if should_delay_declare {
    self.delayed_declares.push_back(self.clock.now(), args);
}
``` [3](#0-2) 

The attacker submits declares from N distinct accounts (each with a fresh nonce), each one incrementally growing `delayed_declares.size_in_bytes()` until the combined total approaches `capacity_in_bytes`.

**Step 3 — Legitimate invoke tx hits the full capacity.**
When a normal user submits an invoke transaction, `add_tx()` again calls `add_ready_declares()` (no-op if delay not expired), then `add_tx_validations()` → `exceeds_capacity()` returns `true`. `handle_capacity_overflow()` is entered:

```rust
fn handle_capacity_overflow(...) -> Result<(), MempoolError> {
    ...
    let creating_gap = (account_has_gap || !account_has_txs) && !closing_gap;
    let required_space = tx.total_bytes().saturating_sub(freed_bytes);
    if !creating_gap && self.try_make_space(required_space) {
        return Ok(());
    }
    Err(MempoolError::MempoolFull)
}
``` [4](#0-3) 

For a fresh account submitting nonce-0 invoke: `account_has_txs = false`, `closing_gap = true` (nonce == account_nonce), so `creating_gap = false`. `try_make_space()` is called.

**Step 4 — `try_make_space` cannot reclaim `delayed_declares` bytes.**
`try_make_space()` exclusively evicts from `tx_pool` by iterating `accounts_with_gap`:

```rust
while total_space_freed < required_space {
    let Some(address) = self.get_evictable_account() else { break; };
    let txs: Vec<_> = self.tx_pool.account_txs_sorted_by_nonce(address)...
``` [5](#0-4) 

If `tx_pool` is empty (all capacity consumed by `delayed_declares`), `get_evictable_account()` returns `None` immediately, `try_make_space()` returns `false`, and `handle_capacity_overflow()` returns `MempoolError::MempoolFull`.

### Impact Explanation
Valid invoke (and deploy-account) transactions from legitimate users are rejected at mempool admission with `MempoolError::MempoolFull` while the mempool's actual sequenceable pool (`tx_pool`) is empty. The sequencer cannot make progress on legitimate user transactions for the duration of the attack (until the declare delay expires and `add_ready_declares()` drains the queue on the next `add_tx` or `get_txs` call). This maps directly to: **High — Mempool/gateway admission rejects valid transactions before sequencing.**

### Likelihood Explanation
The attack requires only the ability to submit declare transactions through the public gateway — no privileges needed. The attacker needs enough distinct accounts (or nonces) to fill `capacity_in_bytes`. Since declare transactions can be large (Sierra class objects), a relatively small number of declares can exhaust capacity. The attack can be sustained by continuously submitting new declares before the delay window expires on the existing ones.

### Recommendation
Decouple `delayed_declares` from the shared capacity budget. Options:
1. **Separate quota**: Give `delayed_declares` its own byte limit (e.g., a fraction of total capacity) and exclude it from `size_in_bytes()` used in `exceeds_capacity()`.
2. **Evictable delayed declares**: Allow `try_make_space()` to also evict entries from `delayed_declares` (lowest-tip-first or FIFO), so the eviction path can reclaim bytes from both sub-stores.
3. **Per-account declare limit**: Enforce a maximum of one pending delayed declare per sender address, bounding the total bytes an individual attacker can park in `delayed_declares`.

### Proof of Concept

```rust
// Pseudocode for a Rust unit test (fee/Starknet mode, not FIFO)
#[test]
fn delayed_declares_exhaust_capacity_blocks_invoke() {
    let capacity = 10_000u64; // small capacity
    let config = MempoolConfig {
        static_config: MempoolStaticConfig {
            capacity_in_bytes: capacity,
            declare_delay: Duration::from_secs(3600), // 1 hour delay
            behavior_mode: BehaviorMode::Starknet,
            ..Default::default()
        },
        ..Default::default()
    };
    let clock = Arc::new(FakeClock::new()); // frozen clock
    let mut mempool = Mempool::new(config, clock);

    // Attacker: submit declare txs from distinct accounts until near capacity.
    // Each declare is ~1000 bytes; submit 9 to consume 9000/10000 bytes.
    for i in 0..9 {
        let declare_args = build_declare_args(account_address(i), nonce(0), size_bytes(1000));
        assert!(mempool.add_tx(declare_args).is_ok());
    }
    // delayed_declares.size_in_bytes() == 9000, tx_pool.size_in_bytes() == 0

    // Legitimate user: submit a 2000-byte invoke tx (would push total to 11000 > 10000).
    let invoke_args = build_invoke_args(account_address(999), nonce(0), size_bytes(2000));
    let result = mempool.add_tx(invoke_args);

    // try_make_space finds no gap accounts in tx_pool → returns false → MempoolFull
    assert_eq!(result, Err(MempoolError::MempoolFull));
}
```

The test demonstrates that `delayed_declares` bytes count against capacity, `try_make_space` cannot reclaim them (only evicts `tx_pool` gap accounts), and the legitimate invoke is rejected despite the sequenceable pool being empty. [6](#0-5)

### Citations

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

**File:** crates/apollo_mempool/src/mempool.rs (L619-630)
```rust
    fn add_ready_declares(&mut self) {
        let now = self.clock.now();
        while let Some((submission_time, _args)) = self.delayed_declares.front() {
            if now - self.config.static_config.declare_delay < *submission_time {
                break;
            }
            let (_submission_time, args) =
                self.delayed_declares.pop_front().expect("Delay declare should exist.");
            self.add_tx_inner(args);
        }
        self.update_state_metrics();
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L918-920)
```rust
    fn size_in_bytes(&self) -> u64 {
        self.tx_pool.size_in_bytes() + self.delayed_declares.size_in_bytes()
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L940-944)
```rust
    fn exceeds_capacity(&self, tx: &InternalRpcTransaction, freed_bytes: u64) -> bool {
        // The to-be-removed transaction is still counted in `size_in_bytes()` here, so subtract
        // what its removal frees. `saturating_sub` guards the (impossible) underflow defensively.
        (self.size_in_bytes() + tx.total_bytes()).saturating_sub(freed_bytes)
            > self.config.static_config.capacity_in_bytes
```

**File:** crates/apollo_mempool/src/mempool.rs (L992-1001)
```rust
    pub fn try_make_space(&mut self, required_space: u64) -> bool {
        let mut total_space_freed = 0;
        let mut evicted_txs = Vec::new();

        while total_space_freed < required_space {
            let Some(address) = self.get_evictable_account() else {
                break;
            };

            let txs: Vec<_> = self.tx_pool.account_txs_sorted_by_nonce(address).copied().collect();
```

**File:** crates/apollo_mempool/src/mempool.rs (L1031-1052)
```rust
    fn handle_capacity_overflow(
        &mut self,
        tx: &InternalRpcTransaction,
        account_nonce: Nonce,
        freed_bytes: u64,
    ) -> Result<(), MempoolError> {
        let address = tx.contract_address();

        let account_has_gap = self.accounts_with_gap.contains(&address);
        let account_has_txs = self.tx_pool.contains_account(address);
        let closing_gap = tx.nonce() == account_nonce;
        let creating_gap = (account_has_gap || !account_has_txs) && !closing_gap;

        // Only the net growth must be evicted: an accompanying replacement removal frees
        // `freed_bytes` (0 when there is no replacement).
        let required_space = tx.total_bytes().saturating_sub(freed_bytes);
        if !creating_gap && self.try_make_space(required_space) {
            return Ok(());
        }

        Err(MempoolError::MempoolFull)
    }
```
