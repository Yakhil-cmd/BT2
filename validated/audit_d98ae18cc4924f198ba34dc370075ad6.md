Let me read the rest of the mempool file and the relevant test to get the complete picture.

### Title
Partial Eviction Without Rollback in `try_make_space` Permanently Removes Valid Third-Party Transactions When Incoming Transaction Is Rejected — (`crates/apollo_mempool/src/mempool.rs`)

---

### Summary

When `handle_capacity_overflow` calls `try_make_space` and the eviction frees *some but not enough* space, those evictions are committed permanently even though the incoming transaction is subsequently rejected with `MempoolFull`. An attacker can exploit this to permanently remove valid third-party gap-account transactions from the mempool without their own transaction ever being accepted. The codebase's own test explicitly acknowledges this behavior.

---

### Finding Description

The call chain in `add_tx_validations` is:

```
add_tx_validations
  → exceeds_capacity(tx, freed_bytes)          // checks net growth
  → handle_capacity_overflow(tx, nonce, freed_bytes)?   // may evict
      → try_make_space(required_space)          // mutates pool permanently
      → if false: return Err(MempoolFull)       // no rollback
  → [error propagates; remove_replaced_tx never called]
``` [1](#0-0) 

Inside `handle_capacity_overflow`, `required_space` is computed as the *net delta* (`new_tx.total_bytes().saturating_sub(freed_bytes)`), and `try_make_space` is called unconditionally when `!creating_gap`: [2](#0-1) 

`try_make_space` removes transactions from gap accounts one by one, accumulating freed bytes. If it exhausts all evictable accounts before reaching `required_space`, it returns `false` — but **all evictions already performed are not rolled back**: [3](#0-2) 

The codebase's own test `rejects_or_accepts_tx_based_on_freed_space` explicitly documents and asserts this behavior: [4](#0-3) 

**Fee-escalation attack path (concrete):**

1. Attacker already has `tx_old` in the mempool: address `A`, nonce `N` (at account nonce, no gap), size `S_old`.
2. Attacker submits replacement `tx_new`: same address `A`, nonce `N`, higher tip/max_l2_gas_price (passes `validate_fee_escalation`), padded with a large signature so `S_new >> S_old`.
3. `freed_bytes = S_old`; `required_space = S_new − S_old` (the delta).
4. `try_make_space(required_space)` evicts third-party gap-account transactions until it runs out of evictable accounts.
5. If total freed < required_space, `try_make_space` returns `false`.
6. `handle_capacity_overflow` returns `Err(MempoolFull)`.
7. `add_tx_validations` propagates the error; `remove_replaced_tx` is never called.
8. **Result:** `tx_old` remains in the pool; `tx_new` is rejected; third-party gap-account transactions are permanently gone.

The `creating_gap` guard does not protect against this: when the attacker's existing tx is at the account nonce, `closing_gap = true` and `creating_gap = false`, so `try_make_space` is always invoked. [5](#0-4) 

---

### Impact Explanation

Valid third-party transactions — previously accepted into the mempool — are permanently removed without being sequenced. The concrete corrupted admission value is the set of evicted gap-account transactions: they existed in the pool, passed all admission checks, and are now gone with no record. Affected users must resubmit. This satisfies **"High. Mempool/gateway/RPC admission … rejects valid transactions before sequencing."**

---

### Likelihood Explanation

The attacker only needs:
- One existing transaction in the mempool at their account nonce (trivially achievable by any user).
- A replacement with a sufficiently large signature and a fee bump that passes `should_replace_tx`.

No operator or privileged access is required. The signature size is an attacker-controlled field with no upper bound enforced at the mempool layer beyond the gateway's stateless size check, and the delta only needs to exceed the aggregate size of gap-account transactions present at the time of the attack.

---

### Recommendation

Collect evicted transactions before calling `try_make_space` and re-insert them (or defer the eviction) if `handle_capacity_overflow` ultimately returns `Err`. Alternatively, perform a dry-run capacity check before mutating the pool: compute whether sufficient evictable bytes exist *before* removing any transaction, and only proceed with eviction if the check passes.

---

### Proof of Concept

The existing test `rejects_or_accepts_tx_based_on_freed_space` already demonstrates the eviction-without-rollback behavior for a fresh transaction. [6](#0-5) 

A fee-escalation-specific reproduction:

```rust
// 1. Add a small tx from attacker's account (address "0x0", nonce 0).
let attacker_tx = add_tx_input!(tx_hash: 1, address: "0x0", tx_nonce: 0, account_nonce: 0);
// 2. Add gap-account txs from third party (address "0x1", nonce 1, account_nonce 0).
let victim_tx = add_tx_input!(tx_hash: 2, address: "0x1", tx_nonce: 1, account_nonce: 0);

// Capacity = attacker_tx + victim_tx.
let capacity = attacker_tx.tx.total_bytes() + victim_tx.tx.total_bytes();
let mut mempool = Mempool::new(MempoolConfig {
    static_config: MempoolStaticConfig {
        capacity_in_bytes: capacity,
        enable_fee_escalation: true,
        fee_escalation_percentage: 10,
        ..Default::default()
    },
    ..Default::default()
}, Arc::new(FakeClock::default()));

add_tx(&mut mempool, &attacker_tx);
add_tx(&mut mempool, &victim_tx);

// 3. Submit replacement with large signature (delta > victim_tx size) and higher fee.
let replacement = AddTransactionArgs {
    tx: internal_invoke_tx(invoke_tx_args!(
        tx_hash: tx_hash!(3),
        sender_address: contract_address!("0x0"),
        nonce: nonce!(0),
        tip: Tip(attacker_tx.tx.tip().0 * 2),
        signature: TransactionSignature(vec![felt!("0x0"); 64].into()),
    )),
    account_state: AccountState { address: contract_address!("0x0"), nonce: nonce!(0) },
};

// 4. Replacement is rejected (delta too large).
add_tx_expect_error(&mut mempool, &replacement, MempoolError::MempoolFull);

// 5. Original attacker tx is still present.
assert!(mempool.tx_pool.get_by_tx_hash(tx_hash!(1)).is_ok());

// 6. Victim's gap-account tx is permanently evicted — BUG.
assert!(
    mempool.tx_pool.get_by_tx_hash(tx_hash!(2)).is_err(),
    "victim tx was permanently evicted even though the replacement was rejected"
);
```

### Citations

**File:** crates/apollo_mempool/src/mempool.rs (L433-444)
```rust
        if self.exceeds_capacity(tx, freed_bytes) {
            self.handle_capacity_overflow(tx, account_nonce, freed_bytes)?;
        }

        // Capacity is confirmed: this is the final, infallible mutation before the incoming
        // transaction is inserted by the caller.
        if let Some(existing_tx_reference) = replaced_tx_reference {
            self.remove_replaced_tx(existing_tx_reference);
        }

        Ok(())
    }
```

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

**File:** crates/apollo_mempool/src/mempool.rs (L1039-1051)
```rust
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
```

**File:** crates/apollo_mempool/src/fee_mempool_test.rs (L1894-1939)
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
}
```
