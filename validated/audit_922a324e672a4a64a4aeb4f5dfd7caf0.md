### Title
Delayed-declare at `account_nonce` suppresses gap detection, making attacker's stuck pool transactions permanently non-evictable — (`crates/apollo_mempool/src/mempool.rs`)

---

### Summary

`update_accounts_with_gap` short-circuits on the first check — `delayed_declares.contains(address, account_nonce)` — and skips the pool-gap test entirely via `continue`. An attacker who places a delayed declare at exactly `nonce = account_nonce` and a higher-nonce invoke in the pool (e.g. nonce=2, account_nonce=0) causes the real gap to go undetected. The account is never inserted into `accounts_with_gap`, so its stuck pool transactions are permanently shielded from eviction, starving legitimate accounts when the pool is full.

---

### Finding Description

The relevant code in `update_accounts_with_gap`: [1](#0-0) 

```
fn update_accounts_with_gap(&mut self, address_to_nonce: AddressToNonce) {
    for (address, account_nonce) in address_to_nonce {
        if self.delayed_declares.contains(address, account_nonce) {   // ← (A)
            self.remove_from_accounts_with_gap(address);
            continue;                                                   // ← (B) skips gap check
        }

        let gap_exists = match self.tx_pool.get_lowest_nonce(address) {
            Some(lowest_nonce) => account_nonce < lowest_nonce,        // ← never reached
            None => false,
        };
        ...
    }
}
```

**Attack steps (all unprivileged):**

1. Attacker submits a `Declare` tx with `nonce=0` while `account_nonce=0`. Because `should_delay_declare` is true in non-FIFO mode, it is pushed to `delayed_declares` and **not** inserted into `tx_pool`. [2](#0-1) 

2. Attacker submits an `Invoke` tx with `nonce=2`. `validate_incoming_tx` passes (nonce 2 ≥ account_nonce 0). The invoke lands in `tx_pool` at nonce=2 but is **not** queued (fee mode only queues `tx_reference.nonce == account_nonce`). [3](#0-2) 

3. `update_accounts_with_gap({attacker: 0})` is called. At line (A), `delayed_declares.contains(attacker, 0)` returns `true`. The function calls `remove_from_accounts_with_gap` (a no-op since the account was never in the gap set) and `continue`s. The pool check — `get_lowest_nonce(attacker)` would return `Some(2)`, and `0 < 2 = true` — is **never evaluated**. [4](#0-3) 

4. The attacker's account is absent from `accounts_with_gap`. `get_evictable_account` only draws from that set, so `try_make_space` cannot touch the attacker's stuck invoke. [5](#0-4) 

5. When the pool fills up, `handle_capacity_overflow` calls `try_make_space`, finds no evictable account (or only evicts unrelated accounts), and returns `MempoolError::MempoolFull` to legitimate submitters. [6](#0-5) 

**Why the gap is never self-healing:**

After the declare delay expires, `add_ready_declares` moves the declare into `tx_pool` but does **not** call `update_accounts_with_gap`. [7](#0-6) 

The next time `update_accounts_with_gap({attacker: 0})` runs, `delayed_declares.contains` is now `false`, but `get_lowest_nonce(attacker)` returns `Some(0)` (the declare), so `gap_exists = (0 < 0) = false`. The gap between nonce=0 and nonce=2 (missing nonce=1) is still invisible. The gap is only detected after the declare is actually sequenced and `account_nonce` advances to 1. [8](#0-7) 

---

### Impact Explanation

The attacker occupies pool capacity with a stuck invoke (nonce=2) that cannot be evicted. When the pool is at capacity, `handle_capacity_overflow` returns `MempoolError::MempoolFull` to legitimate users, causing valid transactions to be rejected. This directly satisfies the **High** impact: *Mempool/gateway/RPC admission rejects valid transactions before sequencing.*

---

### Likelihood Explanation

The attack requires only two standard, unprivileged transactions: one `Declare` (at `account_nonce`) and one `Invoke` (at any higher nonce). No special privileges, keys, or timing beyond the declare delay are needed. The attacker can repeat the pattern with fresh accounts to hold an arbitrarily large fraction of pool capacity.

---

### Recommendation

Remove the unconditional `continue`. Instead, treat the delayed declare as filling the slot at `account_nonce` and then continue to check whether the pool contains any tx with a nonce **higher than `account_nonce`** that has no contiguous predecessor. Concretely, after confirming the delayed declare covers `account_nonce`, check whether `tx_pool.get_lowest_nonce(address)` exists and is greater than `account_nonce + 1` (i.e., a gap exists beyond the declare slot). Only skip gap-insertion if no such higher-nonce pool tx is present.

---

### Proof of Concept

```rust
// Pseudocode Rust unit test outline
#[test]
fn attacker_delayed_declare_suppresses_gap_detection() {
    let mut mempool = /* build mempool with small capacity */;

    // Step 1: attacker submits delayed declare at nonce=0 (account_nonce=0)
    mempool.add_tx(make_declare(attacker, nonce=0, account_nonce=0)).unwrap();

    // Step 2: attacker submits invoke at nonce=2 (gap: nonce=1 missing)
    mempool.add_tx(make_invoke(attacker, nonce=2, account_nonce=0)).unwrap();

    // Assert: attacker's account is NOT in accounts_with_gap despite real gap
    assert!(!mempool.accounts_with_gap().contains(&attacker));

    // Step 3: fill pool with attacker's tx already occupying space
    // Step 4: legitimate user submits tx → should succeed via eviction of attacker's stuck tx
    let result = mempool.add_tx(make_invoke(victim, nonce=0, account_nonce=0));

    // BUG: victim is rejected (MempoolFull) because attacker's gap account is not evictable
    assert!(result.is_err()); // demonstrates the vulnerability
}
```

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

**File:** crates/apollo_mempool/src/mempool.rs (L609-616)
```rust
        } else if tx_reference.nonce == account_nonce {
            // Fee mode: only add transactions with matching account nonce.
            // Remove queued transactions the account might have. This includes old nonce
            // transactions that have become obsolete; those with an equal nonce should
            // already have been removed via fee escalation (`remove_replaced_tx`).
            self.tx_queue.remove_by_address(address);
            self.insert_to_tx_queue(tx_reference);
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

**File:** crates/apollo_mempool/src/mempool.rs (L947-979)
```rust
    fn update_accounts_with_gap(&mut self, address_to_nonce: AddressToNonce) {
        for (address, account_nonce) in address_to_nonce {
            // If a delayed declare transaction exists at the account nonce, it is next to execute,
            // so no gap exists.
            if self.delayed_declares.contains(address, account_nonce) {
                self.remove_from_accounts_with_gap(address);
                continue;
            }

            // Gap exists when lowest transaction nonce is higher than account nonce.
            let gap_exists = match self.tx_pool.get_lowest_nonce(address) {
                Some(lowest_nonce) => account_nonce < lowest_nonce,
                None => false, // No transactions for the account, so no gap.
            };

            // Update the eviction tracking set accordingly.
            if gap_exists {
                if self.accounts_with_gap.insert(address) {
                    // Newly entered gap: all current pool txs for this account are now stuck.
                    let n_stuck = self.tx_pool.n_txs_for_address(address);
                    self.n_stuck_txs += n_stuck;
                    warn!(
                        "Account {address} has a nonce gap; {n_stuck} transaction(s) are now \
                         stuck."
                    );
                }
                // Stayed in gap: per-tx deltas were already applied at add/remove sites.
            } else {
                // Left gap: remaining pool txs for this account are no longer stuck.
                self.remove_from_accounts_with_gap(address);
            }
        }
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L981-988)
```rust
    pub fn get_evictable_account(&self) -> Option<ContractAddress> {
        let len = self.accounts_with_gap.len();
        if len == 0 {
            return None;
        }
        let random_index = rng().random_range(0..len);
        self.accounts_with_gap.get_index(random_index).copied()
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
