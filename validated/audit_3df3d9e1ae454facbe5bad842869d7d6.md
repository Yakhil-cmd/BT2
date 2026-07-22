### Title
Irreversible eviction of gap-account transactions triggered by a rejected oversized transaction — (`crates/apollo_mempool/src/mempool.rs`)

---

### Summary

`Mempool::try_make_space` permanently evicts gap-account transactions to make room for an incoming transaction. If the incoming transaction is ultimately rejected because the freed space is still insufficient, the evictions are **not rolled back**. An unprivileged attacker can exploit this to drain the mempool of legitimate gap-account transactions at zero cost, since the oversized triggering transaction is rejected and no fees are ever charged.

---

### Finding Description

In `handle_capacity_overflow`, when a new transaction exceeds the mempool byte-capacity, the code calls `try_make_space` to evict gap-account transactions:

```rust
// crates/apollo_mempool/src/mempool.rs  lines 1031-1052
fn handle_capacity_overflow(...) -> Result<(), MempoolError> {
    ...
    let creating_gap = (account_has_gap || !account_has_txs) && !closing_gap;
    let required_space = tx.total_bytes().saturating_sub(freed_bytes);
    if !creating_gap && self.try_make_space(required_space) {
        return Ok(());
    }
    Err(MempoolError::MempoolFull)   // ← returned AFTER evictions already happened
}
``` [1](#0-0) 

Inside `try_make_space`, transactions are removed from the pool and queue unconditionally. The function returns `false` when the freed space is still less than `required_space`, but the removals are already committed:

```rust
// crates/apollo_mempool/src/mempool.rs  lines 992-1029
pub fn try_make_space(&mut self, required_space: u64) -> bool {
    ...
    while total_space_freed < required_space {
        ...
        self.tx_pool.remove(tx_ref.tx_hash)...;   // permanent removal
        ...
    }
    self.tx_queue.remove_txs(&evicted_txs);        // permanent removal
    total_space_freed >= required_space            // may be false
}
``` [2](#0-1) 

The production test explicitly documents this broken invariant:

```rust
// crates/apollo_mempool/src/fee_mempool_test.rs  lines 1936-1938
// Transactions tx1 and tx2 are evicted regardless of whether large_tx is accepted or rejected.
// We do not revert the eviction attempt even if adding large_tx ultimately fails.
assert!(!mempool.tx_pool.contains_account(contract_address!("0x1")));
``` [3](#0-2) 

**Attack path:**

1. Attacker controls a valid account at on-chain nonce `N`.
2. Attacker crafts an invoke transaction with nonce `N` and a large signature (up to `max_signature_length = 4000` felts, ≈128 KB).
3. The transaction passes gateway stateless validation (signature ≤ 4000 felts) and stateful validation (`__validate__` runs but no fee is charged for a rejected transaction).
4. `add_tx` is called. `exceeds_capacity` returns `true`. Because `tx.nonce() == account_nonce`, `creating_gap = false`, so `try_make_space` is invoked.
5. `try_make_space` evicts all gap-account transactions it can find, permanently removing them from the pool and queue.
6. If the attacker's transaction is still too large to fit (i.e., the total evictable space < attacker's tx size), `try_make_space` returns `false`, `handle_capacity_overflow` returns `MempoolFull`, and the attacker's transaction is rejected.
7. **The attacker pays zero fees.** The rejected transaction never executes. The attacker's account nonce is unchanged, so the same attack can be repeated immediately with a fresh transaction hash.

The `creating_gap` guard that would prevent eviction only fires when `tx.nonce() > account_nonce`. An attacker submitting at the correct nonce always bypasses it. [4](#0-3) 

The gateway stateless limit that bounds the attacker's transaction size: [5](#0-4) 

---

### Impact Explanation

**High — Mempool admission rejects valid transactions before sequencing.**

An unprivileged attacker can permanently evict legitimate gap-account transactions from the mempool at zero per-iteration cost. Accounts that submit future-nonce transactions (e.g., nonce 1 before nonce 0 is committed, a common pattern in deploy-account + invoke UX flows) will have their transactions repeatedly evicted before they can be sequenced. The attacker only needs to maintain a non-zero balance to pass the gateway fee-bound check; no fees are ever deducted because the triggering transaction is rejected at the mempool layer.

---

### Likelihood Explanation

The attack is feasible whenever the total byte-size of gap-account transactions in the mempool is smaller than the attacker's maximum transaction size (~128 KB with a 4000-felt signature). This condition is easily engineered: the attacker can wait for a low-gap-account period or target a freshly started node. The attack is repeatable with zero marginal cost per iteration.

---

### Recommendation

Roll back evictions when the triggering transaction is ultimately rejected. One approach: collect the evicted transactions inside `try_make_space` and re-insert them into the pool and queue if `handle_capacity_overflow` is about to return `MempoolFull`. Alternatively, perform a dry-run capacity check before evicting: only call `try_make_space` if `required_space ≤ total_evictable_bytes`, so eviction is never attempted when it cannot succeed.

---

### Proof of Concept

The existing test `rejects_or_accepts_tx_based_on_freed_space` in `crates/apollo_mempool/src/fee_mempool_test.rs` (lines 1894–1938) directly demonstrates the vulnerability. The `insufficient_eviction_space` case (signature size = 20 felts) shows that `tx1` and `tx2` (gap-account transactions) are permanently evicted even though `large_tx` is rejected with `MempoolError::MempoolFull`. The test comment on line 1936 explicitly acknowledges: *"We do not revert the eviction attempt even if adding large_tx ultimately fails."* [6](#0-5)

### Citations

**File:** crates/apollo_mempool/src/mempool.rs (L992-1029)
```rust
    pub fn try_make_space(&mut self, required_space: u64) -> bool {
        let mut total_space_freed = 0;
        let mut evicted_txs = Vec::new();

        while total_space_freed < required_space {
            let Some(address) = self.get_evictable_account() else {
                break;
            };

            let txs: Vec<_> = self.tx_pool.account_txs_sorted_by_nonce(address).copied().collect();
            for tx_ref in txs.iter().rev() {
                let tx = self
                    .tx_pool
                    .remove(tx_ref.tx_hash)
                    .expect("Transaction must exist in the pool.");
                total_space_freed += tx.total_bytes();
                evicted_txs.push(*tx_ref);
                metric_count_evicted_txs(1);
                self.decrement_stuck_txs_if_gap_account(address, 1);
                if total_space_freed >= required_space {
                    break;
                }
            }

            // Clean up if account is now empty.
            if !self.tx_pool.contains_account(address) {
                self.accounts_with_gap.swap_remove(&address);
            }
        }

        // Keep the queue consistent with the pool: the evicted txs were removed from the pool, so
        // drop their (now-orphaned) queue references too. In fee mode gap accounts are never
        // queued, so this is a no-op there; in Echonet/FIFO mode they are, and skipping this leaves
        // a dangling reference that panics the next `get_txs`.
        self.tx_queue.remove_txs(&evicted_txs);

        total_space_freed >= required_space
    }
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

**File:** crates/apollo_mempool/src/fee_mempool_test.rs (L1894-1938)
```rust
#[rstest]
#[case::insufficient_eviction_space(20, false)]
#[case::sufficient_eviction_space(8, true)]
fn rejects_or_accepts_tx_based_on_freed_space(
    #[case] signature_size: usize,
    #[case] expect_success: bool,
) {
    let tx1 = add_tx_input!(tx_hash: 1, address: "0x1", tx_nonce: 1, account_nonce: 0);
    let tx2 = add_tx_input!(tx_hash: 2, address: "0x1", tx_nonce: 2, account_nonce: 0);

    let large_signature = vec![felt!("0x0"); signature_size];
    let large_tx = AddTransactionArgs {
        tx: internal_invoke_tx(invoke_tx_args!(
            tx_hash: tx_hash!(3),
            signature: TransactionSignature(large_signature.into())
        )),
        account_state: AccountState { address: contract_address!("0x0"), nonce: nonce!(0) },
    };

    let capacity = tx1.tx.total_bytes() + tx2.tx.total_bytes();
    let mut mempool = Mempool::new(
        MempoolConfig {
            static_config: MempoolStaticConfig {
                capacity_in_bytes: capacity,
                ..Default::default()
            },
            ..Default::default()
        },
        Arc::new(FakeClock::default()),
    );

    for tx in [&tx1, &tx2] {
        add_tx(&mut mempool, tx);
    }

    if expect_success {
        add_tx(&mut mempool, &large_tx);
        assert!(mempool.tx_pool.get_by_tx_hash(large_tx.tx.tx_hash()).is_ok());
    } else {
        add_tx_expect_error(&mut mempool, &large_tx, MempoolError::MempoolFull);
    }

    // Transactions tx1 and tx2 are evicted regardless of whether large_tx is accepted or rejected.
    // We do not revert the eviction attempt even if adding large_tx ultimately fails.
    assert!(!mempool.tx_pool.contains_account(contract_address!("0x1")));
```

**File:** crates/apollo_gateway_config/src/config.rs (L195-195)
```rust
            max_signature_length: 4000,
```
