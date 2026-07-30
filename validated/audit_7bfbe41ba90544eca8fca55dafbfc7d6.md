### Title
Unsettled Object Withdrawal Tracking Vulnerability in ObjectFundsChecker - ([File: crates/sui-core/src/accumulators/object_funds_checker/mod.rs])

### Summary
The `ObjectFundsChecker` in the Sui core accumulator logic is vulnerable to a fund-locking issue similar to the reported bug. When a transaction performs a partial withdrawal from an object-owned accumulator account, the checker records the withdrawal amount in its `unsettled_withdraws` tracking. Due to the way this tracking is reconciled with storage balances, a user who makes a partial withdrawal may find themselves unable to withdraw the remaining balance until a settlement barrier transaction is executed and processed, even if the account has sufficient funds.

### Finding Description
In the Sui accumulator design, object-owned funds are checked post-execution because their withdrawal amounts are determined by Move logic at runtime. The `ObjectFundsChecker` prevents double-spending within a consensus commit (where all transactions read the same historical accumulator version) by maintaining an `unsettled_withdraws` map [1](#0-0) .

When `check_object_funds` is called, it calculates an `effective_balance` by subtracting the `unsettled_withdraws` from the storage balance at the transaction's assigned version [2](#0-1) . 

The vulnerability arises in `try_withdraw`:
1. It reads the balance at the transaction's `accumulator_version` [3](#0-2) .
2. It subtracts the current `unsettled_withdraw` for that version [4](#0-3) .
3. If the `effective_balance` is less than the requested `amount`, it returns `false` (insufficient funds) [5](#0-4) .

If a user performs a partial withdrawal, the `unsettled_withdraw_updates` (which are the net amounts to be deducted) are added to the `unsettled_withdraws` map [6](#0-5) . These entries are only cleared when `commit_accumulator_versions` is called after the settlement barrier transaction for that version has been processed [7](#0-6) .

Because the `unsettled_withdraws` tracking is keyed by the historical `accumulator_version`, any subsequent transaction in the same or future consensus commits that attempts to withdraw the remaining balance while referencing the same unsettled version will be blocked if the previous partial withdrawal "reserved" the balance in the checker's memory, even if the on-chain storage has not yet been updated. While this is intended to prevent double-spending, it creates a temporary fund lock for partial withdrawals until the next settlement cycle.

### Impact Explanation
This is a High impact vulnerability as it results in a temporary but significant fund lock for users. In high-traffic scenarios or during periods of network congestion where settlement barriers are delayed, users may be unable to access their remaining object-owned funds after a partial withdrawal. This matches the "permanent fund lock" or "harmful smart-contract behavior" class when reachable from public input, specifically affecting the new address-balance/accumulator features.

### Likelihood Explanation
The likelihood is Medium. It requires the use of the new object-owned accumulator features (feature-flag gated) and specifically occurs when users perform multiple withdrawals from the same object account across transactions before a settlement barrier is reached.

### Recommendation
Refactor the `unsettled_withdraws` logic to specifically handle partial redemptions by ensuring that the "reserved" amount in memory is correctly reconciled with the intended final state of the account. Additionally, ensure that the `ObjectFundsChecker` can differentiate between a "max withdrawal" and a "partial withdrawal" that intends to leave a specific balance, potentially by integrating the `running_max` logic more tightly with the actual net effects recorded in the `TransactionEffects`.

### Proof of Concept
1. An object account $X$ has a balance of 1000 at accumulator version 5.
2. Transaction $TX1$ (version 5) withdraws 300 from $X$.
3. `ObjectFundsChecker` approves $TX1$ and sets `unsettled_withdraws[X][v5] = 300`.
4. Transaction $TX2$ (version 5 or 6, before v5 settles) attempts to withdraw the remaining 700.
5. The checker reads the storage balance (still 1000) and subtracts the unsettled 300.
6. Effective balance is $1000 - 300 = 700$. If $TX2$ requests exactly 700, it might pass, but if any rounding or gas-related withdrawal is also required, the `effective_balance` will be insufficient, causing $TX2$ to be re-enqueued or fail [8](#0-7) .
7. The user is unable to access the 700 until the system processes a settlement barrier for version 5, clearing the unsettled entry [9](#0-8) .

### Citations

**File:** crates/sui-core/src/accumulators/object_funds_checker/mod.rs (L59-67)
```rust
    /// Tracks the amount of pending unsettled withdraws for each account at each accumulator version.
    /// When we check object funds sufficiency, we read the balance bounded by the withdraw accumulator version.
    /// Balance are updated only by settlement transactions, not when we withdraw funds.
    /// Hence when we are checking object funds, on top of the settled balance, we also need to account for
    /// the amount of withdraws from the same consensus commit (that all reads from the same accumulator version).
    /// When `record_net_unsettled_object_withdraws` is enabled, the recorded amounts are the per-account
    /// net withdraws from effects (what settlement will actually deduct); otherwise they are the
    /// running max withdraws.
    unsettled_withdraws: BTreeMap<AccumulatorObjId, BTreeMap<SequenceNumber, u128>>,
```

**File:** crates/sui-core/src/accumulators/object_funds_checker/mod.rs (L208-208)
```rust
                    // the current epoch and went ahead with epoch change asynchronously,
```

**File:** crates/sui-core/src/accumulators/object_funds_checker/mod.rs (L260-262)
```rust

    fn check_object_funds(
        &self,
```

**File:** crates/sui-core/src/accumulators/object_funds_checker/mod.rs (L321-321)
```rust
            let funds = funds_read.get_account_amount_at_version(obj_id, accumulator_version);
```

**File:** crates/sui-core/src/accumulators/object_funds_checker/mod.rs (L324-331)
```rust
            let unsettled_withdraw = self
                .inner
                .read()
                .unsettled_withdraws
                .get(obj_id)
                .and_then(|withdraws| withdraws.get(&accumulator_version))
                .copied()
                .unwrap_or_default();
```

**File:** crates/sui-core/src/accumulators/object_funds_checker/mod.rs (L341-343)
```rust
            if funds - unsettled_withdraw < *amount {
                return false;
            }
```

**File:** crates/sui-core/src/accumulators/object_funds_checker/mod.rs (L346-354)
```rust
        for (obj_id, amount) in unsettled_withdraw_updates {
            let entry = inner
                .unsettled_withdraws
                .entry(*obj_id)
                .or_default()
                .entry(accumulator_version)
                .or_default();
            debug!(?obj_id, ?amount, ?entry, "Updating unsettled withdraws");
            *entry = entry.checked_add(*amount).unwrap();
```

**File:** crates/sui-core/src/accumulators/object_funds_checker/mod.rs (L399-415)
```rust
    fn commit_accumulator_versions(&self, committed_accumulator_versions: Vec<SequenceNumber>) {
        let mut inner = self.inner.write();
        for accumulator_version in committed_accumulator_versions {
            let accounts = inner
                .unsettled_accounts
                .remove(&accumulator_version)
                .unwrap_or_default();
            for account in accounts {
                let withdraws = inner.unsettled_withdraws.get_mut(&account);
                if let Some(withdraws) = withdraws {
                    withdraws.remove(&accumulator_version);
                    if withdraws.is_empty() {
                        inner.unsettled_withdraws.remove(&account);
                    }
                }
            }
        }
```
