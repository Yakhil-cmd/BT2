### Title
Uncertified/reorg'd chunks whose entries are never subtracted from `PendingTransactionQueue` permanently lock accounts and gas keys out of transaction admission - ([File: chain/client/src/pending_transaction_queue.rs])

### Summary
`PendingTransactionQueue` maintains cached aggregate counters (`pending_accounts`, `pending_nonces`, `pending_gas_key_costs`) that are incremented in `add_chunk_transactions` when a chunk is included in a block, and decremented in `remove_certified_chunk_by_block_hash` only when that specific chunk later becomes certified. This mirrors the SpiceAuction `_totalAuctionTokenAllocation` pattern: a running total is bumped on one code path and is only unwound by a second, narrower code path keyed to a specific identifier (`block_hash` / auction epoch id). If a chunk that was added via `add_chunk_transactions` is ever discarded (e.g. it belongs to a fork that is abandoned, or otherwise never reaches the "certified" callback), its contribution to `pending_accounts`, `pending_gas_key_costs`, and `pending_nonces` is never removed by `remove_certified_chunk_by_block_hash`, because that function is looked up purely `by_block_hash` and does nothing but log-and-return if the hash is missing.

### Finding Description
`add_chunk_transactions` merges a chunk's per-account and per-gas-key aggregates into the queue-wide totals unconditionally, and stores the chunk's raw data keyed by `block_hash` in `self.chunks` [1](#0-0) .

The only way to reverse that contribution is `remove_certified_chunk_by_block_hash`, which looks up `self.chunks.remove(block_hash)`; if the hash is not found it just logs a debug message and returns without touching `pending_accounts` / `pending_gas_key_costs` / `pending_nonces` [2](#0-1) . This means correctness depends entirely on every chunk that was ever added being certified (removed) under the exact same `block_hash` it was added with. There is no bounding/expiry mechanism analogous to the Solidity contract's `epochs[id]` bookkeeping — the only escape hatch is a full `clear()` (used "for reorg re-initialization") that wipes everything at once, rather than surgically removing the specific stale chunk [3](#0-2) .

These cached totals directly gate transaction admission: `query_pending_state`/`get_pending_constraints` feed `paid_from_balance` and `pending_gas_key_cost` into `verify_and_charge_gas_key_tx_ephemeral`, which rejects a transaction with `NotEnoughGasKeyBalance` whenever `gas_key_info.balance.checked_sub(pending.paid_from_gas_key)` underflows or is less than the tx's cost [4](#0-3) . Likewise `PendingAccount` counters gate the P_MAX / deploy-exclusivity admission logic in `PendingTxSession::check_pending` [5](#0-4) .

This is the direct Rust analog of the reported Solidity bug class: a cached aggregate (`_totalAuctionTokenAllocation` / `pending_gas_key_costs`) is bumped on an "add" path but the "remove" path is conditioned on a narrow key match (`auctionConfigs[id]` deletion / `self.chunks.remove(block_hash)`), so any chunk/epoch that doesn't go through the expected removal path leaves the aggregate permanently inflated. In the Solidity case this locks auction tokens; here it would permanently inflate `pending_gas_key_costs`/`paid_from_balance` for an account, causing the RPC/chunk-production admission path to reject all further valid gas-key or access-key transactions from that account with `NotEnoughGasKeyBalance` or `Skip` (P_MAX exhaustion) — an accounting/DoS lock rather than a token-theft, but structurally the same root cause (asymmetric add/remove of a cached total keyed by an identifier that can be silently dropped).

### Impact Explanation
If the invariant "every `add_chunk_transactions` call is eventually matched by exactly one `remove_certified_chunk_by_block_hash` for the same `block_hash`" is violated (e.g., transactions from an orphaned/reorg'd chunk that isn't handled by the coarse `clear()` reset, or a chunk hash collision/miss), the affected account's or gas key's pending totals become permanently inflated. Consequences:
- The account/gas key is locked out of submitting further transactions via the RPC handler (`NotEnoughGasKeyBalance`, P_MAX/deploy-exclusivity `Skip`) even though its actual on-chain trie balance is sufficient — a persistent denial of service against that account.
- Because the debug-assert-and-default fallback (`checked_sub_or_default!`) silently resets to `Default::default()` on underflow rather than propagating an error, any accounting error is masked in production builds (`debug_assert!` is a no-op in release), making the corruption silent and hard to detect except via the `tracing::error!` log line.

This does not directly enable token theft/inflation (the underlying trie state is unaffected), but it does enable state-accounting divergence and account-level chain-stall/DoS for valid transaction submission, consistent with the "node panic or unbounded resource use / chain stall / state divergence" impact bar.

### Likelihood Explanation
This requires a fork/reorg scenario in which a chunk that was included in `add_chunk_transactions` never later triggers `remove_certified_chunk_by_block_hash` for its exact `block_hash` (e.g. because the block is abandoned rather than certified, or because certification is keyed differently than inclusion). I was not able to fully verify — due to running out of investigation iterations — whether `clear()` (the reorg re-initialization path) is guaranteed to be invoked on every code path that can orphan a chunk after `add_chunk_transactions` was called for it, nor whether `remove_certified_chunk_by_block_hash` is guaranteed to be called exactly once per added chunk under all Spice/ChunkProducer flows in `client.rs` and `chunk_producer.rs`. This is gated behind the `protocol_feature_spice` feature (tests are `#[cfg_attr(not(feature = "protocol_feature_spice"), ignore)]`), reducing current exposure, but the code is present and reachable via the described transaction/chunk-production path once the feature is enabled.

### Recommendation
- Audit every call site that can cause a chunk to become "abandoned" (fork loss, chunk unavailability, reorg) after `add_chunk_transactions` was called for it, and ensure `remove_certified_chunk_by_block_hash` (or an equivalent per-chunk reversal) is always invoked for that exact `block_hash`, not just on certification success.
- Replace the silent `checked_sub_or_default!` fallback with a hard invariant violation (panic in debug, and a metric/alert in release) so any accounting drift is immediately visible instead of being masked.
- Consider adding a reconciliation/expiry mechanism (e.g., dropping `self.chunks` entries and their aggregate contributions once a block height/hash provably cannot be certified anymore) instead of relying solely on exact-match removal plus a full `clear()`.

### Proof of Concept
Not independently reproduced; this analysis is based on static code review of `add_chunk_transactions` / `remove_certified_chunk_by_block_hash` / `clear()` in `chain/client/src/pending_transaction_queue.rs` and their consumers in `runtime/runtime/src/verifier.rs`. A concrete PoC would require constructing a Spice-feature test-loop scenario where a chunk is included via `add_chunk_transactions`, the containing block is subsequently orphaned by a reorg without triggering `remove_certified_chunk_by_block_hash` for that block hash or a `clear()`, and then demonstrating that the affected account's subsequent valid transactions are rejected with `NotEnoughGasKeyBalance`/`Skip` despite sufficient on-chain balance. I was unable to build/run this PoC within the available tooling (no filesystem/test execution access), so this should be validated by a background engineering session with full repo and test-execution access before being treated as confirmed.

### Citations

**File:** chain/client/src/pending_transaction_queue.rs (L296-314)
```rust
        // Merge chunk data into pending transaction queue totals.
        for (account_id, chunk_account) in &chunk_data.accounts {
            let total_account = self.pending_accounts.entry(account_id.clone()).or_default();
            total_account.add(chunk_account);
        }
        for (nonce_key, &chunk_nonce) in &chunk_data.nonces {
            self.pending_nonces.entry(nonce_key.clone()).or_default().add(chunk_nonce);
        }
        for (gas_key, &chunk_gas_key_cost) in &chunk_data.gas_key_costs {
            let entry = self.pending_gas_key_costs.entry(gas_key.clone()).or_insert(Balance::ZERO);
            *entry = entry.saturating_add(chunk_gas_key_cost);
        }

        debug_assert!(
            !self.chunks.contains_key(&block_hash),
            "duplicate block_hash in pending transaction queue"
        );
        self.chunks.insert(block_hash, chunk_data);
    }
```

**File:** chain/client/src/pending_transaction_queue.rs (L316-325)
```rust
    /// Remove a certified chunk's transactions from the pending transaction queue.
    pub fn remove_certified_chunk_by_block_hash(&mut self, block_hash: &CryptoHash) {
        let Some(chunk_data) = self.chunks.remove(block_hash) else {
            tracing::debug!(
                target: "client",
                ?block_hash,
                "chunk not found in pending transaction queue during removal"
            );
            return;
        };
```

**File:** chain/client/src/pending_transaction_queue.rs (L361-367)
```rust
    /// Clear all pending transaction data (used for reorg re-initialization).
    pub fn clear(&mut self) {
        self.chunks.clear();
        self.pending_accounts.clear();
        self.pending_nonces.clear();
        self.pending_gas_key_costs.clear();
    }
```

**File:** chain/client/src/pending_transaction_queue.rs (L493-507)
```rust
        // Deploy exclusivity: a deploy cannot coexist with any other access
        // key tx (including another deploy) in the pending window.
        if !is_gas_key_tx {
            if total_deploy_count > 0 {
                return PendingTxCheckResult::Skip;
            }
            if tx_has_deploy && total_access_key_count > 0 {
                return PendingTxCheckResult::Skip;
            }
        }

        // P_MAX for contract accounts.
        if has_contract == HasContract::Yes && !is_gas_key_tx && total_access_key_count >= P_MAX {
            return PendingTxCheckResult::Skip;
        }
```

**File:** runtime/runtime/src/verifier.rs (L420-440)
```rust

    // Check gas key has enough balance for gas costs, accounting for
    // pending gas key costs (prior gas key txs + pending WithdrawFromGasKey).
    // Unlike account balance, gas key balance only changes through transactions
    // that PTQ explicitly tracks, so pending should never exceed the balance.
    let Some(available_gas_key_balance) =
        gas_key_info.balance.checked_sub(pending.paid_from_gas_key)
    else {
        tracing::error!(
            target: "runtime",
            balance = %gas_key_info.balance,
            paid_from_gas_key = %pending.paid_from_gas_key,
            "pending gas key costs exceed gas key balance"
        );
        return TxVerdict::Failed(InvalidTxError::NotEnoughGasKeyBalance {
            signer_id: account_id.clone(),
            balance: Balance::ZERO,
            cost: gas_cost,
        });
    };
    if available_gas_key_balance < gas_cost {
```
