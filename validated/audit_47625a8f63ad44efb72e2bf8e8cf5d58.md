### Title
Transaction pool admits multiple mutually-exclusive transactions from one signer without aggregate balance checking, enabling shared mempool exhaustion - ([File: chain/client/src/rpc_handler.rs])

### Summary
`nearcore`'s RPC transaction-submission path validates each incoming transaction's balance against the last committed/certified chain state only, without accounting for the cumulative cost of that signer's *other* transactions already sitting, unconfirmed, in the same shard's transaction pool. This mirrors the `op-geth` `validateMetaTxList` bug class: many transactions are each individually "valid" but only one of them can actually succeed once included in a chunk, yet all are accepted and retained in a shared, size-limited pool.

### Finding Description
When a transaction reaches `process_tx` in `chain/client/src/rpc_handler.rs`, the code chooses the constraints used for balance validation: [1](#0-0) 
For the non-SPICE path (the default; `spice_pending_transaction_queue_enabled` is `false` by default and gated behind the `protocol_feature_spice` cargo feature), `PendingConstraints::default()` is used unconditionally, meaning `paid_from_balance` is `Balance::ZERO` regardless of how many other pending transactions from the same signer/account already occupy the pool: [2](#0-1) 

`can_verify_and_charge_tx` then calls into `verify_and_charge_tx_ephemeral`, which computes `available_balance` as `account.amount().saturating_sub(pending.paid_from_balance)` — with `paid_from_balance` being zero on this path, the check is effectively "does the signer's on-chain balance cover this one transaction," with no visibility into sibling transactions already queued: [3](#0-2) 

If the check passes, the transaction is inserted into the shared `TransactionPool`, which enforces only a total byte-size cap shared across all signers on the shard — there is no aggregate feasibility check at insertion time: [4](#0-3) 

The codebase's own test explicitly demonstrates that the pool accepts multiple transactions whose combined cost exceeds the shared balance, and that only one is ultimately selected when a chunk is produced (the ephemeral overlay used by `prepare_transactions` correctly shares balance *within a single chunk-production pass*, but this happens only after admission, once per chunk): [5](#0-4) 

The proper fix for this — a `PendingTransactionQueue` (`PendingConstraints.paid_from_balance`) that aggregates uncertified/pending transaction costs per account/gas-key across the pool — already exists in the codebase, but it is exclusively wired into the `Spice` protocol-feature path and disabled by default: [6](#0-5) [7](#0-6) 

Outside of that opt-in feature, an ordinary (non-SPICE) validator/RPC node has no mechanism at the RPC-admission stage to reject a batch of individually-valid-but-jointly-infeasible transactions from a single signer.

### Impact Explanation
A low-balance account (or an account/gas-key holder) can craft many transactions from the same signer/nonce-space, each independently within the currently committed balance, but whose sum vastly exceeds it (e.g., N transfers of `0.6 * balance` each). All N will be individually accepted by RPC validation and inserted into the shared, size-limited transaction pool (`total_transaction_size_limit`), which is a **shared resource across all accounts on that shard**, not a per-account quota. This lets an attacker cheaply occupy a disproportionate share of pool capacity with transactions that are guaranteed to mostly fail during chunk production, causing legitimate transactions from *other* users to be rejected with `InsertTransactionResult::NoSpaceLeft`: [8](#0-7) 
This is a resource-exhaustion / degraded-throughput ("chain stall") vector reachable purely through normal RPC transaction submission by an unprivileged account, requiring no validator or node compromise.

### Likelihood Explanation
The scenario is straightforward to trigger: an attacker only needs one account with a modest balance and the ability to sign many transactions with increasing nonces (a cheap, unprivileged operation). Because the RPC/mempool admission path performs no aggregate balance accounting outside the SPICE-only `PendingTransactionQueue`, and that mechanism is disabled by default, this path is exercised on any standard nearcore deployment. However, real-world severity is bounded compared to the `op-geth` original: nearcore discards the excess/failing transactions rather than persisting them indefinitely (they are not returned to the pool after a failed chunk-production attempt), so the attacker must continuously resubmit fresh batches to sustain pool pressure, rather than achieving a single persistent stall.

### Recommendation
Wire the existing `PendingTransactionQueue` / `PendingConstraints.paid_from_balance` aggregation into the non-SPICE (default) RPC validation and pool-admission path as well, so that `process_tx` accounts for the signer's already-pooled, uncertified transaction costs before accepting a new one — not only under the `protocol_feature_spice` opt-in. Alternatively, enforce a per-signer cap on pool occupancy/byte-size so a single account cannot monopolize the shared `total_transaction_size_limit` with mutually-exclusive transactions.

### Proof of Concept
1. Create an account `alice` with balance `B`.
2. Craft `N` `SignedTransaction::send_money` transactions, each with a distinct nonce, each transferring `0.6 * B` to arbitrary receivers (as in `test_prepare_transactions_shared_balance_across_keys`, generalized to N transactions instead of 2, potentially reusing multiple access keys to raise N further).
3. Submit all `N` via RPC. Since `process_tx` uses `PendingConstraints::default()` on the non-SPICE path, each transaction passes `can_verify_and_charge_tx` independently and is inserted into `ShardedTransactionPool`, consuming pool size budget shared with other users.
4. Observe: only one transaction is ultimately included in the next produced chunk (per the ephemeral-overlay balance-sharing behavior demonstrated in `test_prepare_transactions_shared_balance_across_keys`), while pool space was occupied by all `N` in the interim; repeating this continuously with fresh batches can keep the shared pool near its size limit, degrading admission of legitimate transactions from other accounts.

### Citations

**File:** chain/client/src/rpc_handler.rs (L237-262)
```rust
                let constraints = if self.config.spice_pending_transaction_queue_enabled {
                    let ptq = self.pending_transaction_queue.lock();
                    ptq.get(&shard_uid)
                        .map(|q| q.get_pending_constraints(&signed_tx))
                        .unwrap_or_default()
                } else {
                    PendingConstraints::default()
                };
                (root, constraints)
            } else {
                let chunk_store = self.chain_store.chunk_store();
                let root = match chunk_store.get_chunk_extra(&head.last_block_hash, &shard_uid) {
                    Ok(chunk_extra) => *chunk_extra.state_root(),
                    Err(_) => {
                        if is_forwarded {
                            return Err(near_client_primitives::types::Error::Other(
                                "Node has not caught up yet".to_string(),
                            ));
                        } else {
                            self.forward_tx(&epoch_id, signed_tx)?;
                            return Ok(ProcessTxResponse::RequestRouted);
                        }
                    }
                };
                (root, PendingConstraints::default())
            };
```

**File:** chain/client/src/rpc_handler.rs (L278-296)
```rust
            if self.is_chunk_producer_for_transaction(&head, signed_tx.transaction.signer_id())? {
                let mut pool = self.tx_pool.lock();
                match pool.insert_transaction(shard_uid, validated_tx) {
                    InsertTransactionResult::Success => {
                        tracing::trace!(target: "client", ?shard_uid, tx_hash = ?signed_tx.get_hash(), "recorded a transaction");
                    }
                    InsertTransactionResult::Duplicate => {
                        tracing::trace!(target: "client", ?shard_uid, tx_hash = ?signed_tx.get_hash(), "duplicate transaction, not forwarding it");
                        return Ok(ProcessTxResponse::ValidTx);
                    }
                    InsertTransactionResult::NoSpaceLeft => {
                        if is_forwarded {
                            tracing::trace!(target: "client", ?shard_uid, tx_hash = ?signed_tx.get_hash(), "transaction pool is full, dropping the transaction");
                        } else {
                            tracing::trace!(target: "client", ?shard_uid, tx_hash = ?signed_tx.get_hash(), "transaction pool is full, trying to forward the transaction");
                        }
                    }
                }
            }
```

**File:** core/chain-configs/src/client_config.rs (L845-860)
```rust
impl ClientConfig {
    pub fn spice_pending_transaction_queue_enabled(&self) -> bool {
        #[cfg(feature = "protocol_feature_spice")]
        return self.spice_pending_transaction_queue_enabled;
        #[cfg(not(feature = "protocol_feature_spice"))]
        false
    }

    #[cfg(feature = "protocol_feature_spice")]
    pub fn set_spice_pending_transaction_queue_enabled(&mut self, value: bool) {
        self.spice_pending_transaction_queue_enabled = value;
    }

    #[cfg(not(feature = "protocol_feature_spice"))]
    pub fn set_spice_pending_transaction_queue_enabled(&mut self, _value: bool) {}
}
```

**File:** runtime/runtime/src/verifier.rs (L307-317)
```rust
    // saturating_sub is fine here: on the consensus path pending constraints
    // are always default (zero), so the subtraction is exact. On the RPC /
    // chunk-production path it is best-effort and does not affect consensus.
    let available_balance = account.amount().saturating_sub(pending.paid_from_balance);
    if available_balance < total_cost {
        return TxVerdict::Failed(InvalidTxError::NotEnoughBalance {
            signer_id: account_id.clone(),
            balance: available_balance,
            cost: total_cost,
        });
    }
```

**File:** chain/pool/src/lib.rs (L87-127)
```rust
    /// Inserts a signed transaction that passed validation into the pool.
    pub fn insert_transaction(
        &mut self,
        validated_tx: ValidatedTransaction,
    ) -> InsertTransactionResult {
        let tx_hash = validated_tx.get_hash();
        if self.unique_transactions.contains(&tx_hash) {
            return InsertTransactionResult::Duplicate;
        }
        // We never expect the total size to go over `u64` during real operation as that would
        // be more than 10^9 GiB of RAM consumed for transaction pool, so panicking here is intended
        // to catch a logic error in estimation of transaction size.
        let new_total_transaction_size = self
            .total_transaction_size
            .checked_add(validated_tx.wire_size())
            .expect("Total transaction size is too large");
        if let Some(limit) = self.total_transaction_size_limit {
            if new_total_transaction_size > limit {
                return InsertTransactionResult::NoSpaceLeft;
            }
        }

        // At this point transaction is accepted to the pool.

        // This is guaranteed to succeed because of the check above that the
        // hashset does not contain this hash.  This can be improved once the
        // entries API is stabilized
        // (https://github.com/rust-lang/rust/issues/60896).
        assert_eq!(self.unique_transactions.insert(tx_hash), true);
        self.total_transaction_size = new_total_transaction_size;
        let signer_id = validated_tx.signer_id();
        let signer_public_key = validated_tx.public_key();
        self.transactions
            .entry(self.key(signer_id, signer_public_key, validated_tx.nonce().nonce_index()))
            .or_insert_with(Vec::new)
            .push(validated_tx);

        self.transaction_pool_count_metric.inc();
        self.transaction_pool_size_metric.set(self.total_transaction_size as i64);
        InsertTransactionResult::Success
    }
```

**File:** chain/chain/src/runtime/tests.rs (L1760-1800)
```rust
/// When the same account has transactions under two different public keys,
/// the signer cache must share account state (balance) across keys.
/// Otherwise each key's group sees the full balance independently.
#[test]
fn test_prepare_transactions_shared_balance_across_keys() {
    let (mut env, chain, _) = get_test_env_with_chain_and_pool();

    let account_id: AccountId = "test1".parse().unwrap();
    let signer1 = InMemorySigner::test_signer(&account_id);
    let signer2 =
        InMemorySigner::from_seed(account_id.clone(), near_crypto::KeyType::ED25519, "second_key");
    let block_hash = env.head.prev_block_hash;

    // Add a second full-access key for the same account directly in the trie.
    let shard_layout = env.epoch_manager.get_shard_layout_from_prev_block(&block_hash).unwrap();
    let shard_id = shard_layout.shard_ids().next().unwrap();
    let shard_uid =
        shard_id_to_uid(env.epoch_manager.as_ref(), shard_id, &env.head.epoch_id).unwrap();
    {
        let trie = env.runtime.tries.get_trie_for_shard(shard_uid, env.state_roots[0]);
        let mut state_update = TrieUpdate::new(trie);
        near_store::set_access_key(
            &mut state_update,
            account_id.clone(),
            signer2.public_key(),
            &AccessKey::full_access(),
        );
        state_update.commit(StateChangeCause::InitialState);
        let trie_changes = state_update.finalize().unwrap().trie_changes;
        let mut store_update = env.runtime.tries.store_update();
        env.state_roots[0] =
            env.runtime.tries.apply_all(&trie_changes, shard_uid, &mut store_update);
        store_update.commit();
    }

    // Each transfer exceeds half the available balance, so only one can succeed
    // if the balance is shared. With independent balances both would succeed.
    let available = TESTING_INIT_BALANCE.checked_sub(TESTING_INIT_STAKE).unwrap();
    let transfer_amount =
        available.checked_div(2).unwrap().checked_add(Balance::from_near(1)).unwrap();
    let receiver: AccountId = "test2".parse().unwrap();
```

**File:** chain/client/src/pending_transaction_queue.rs (L440-461)
```rust
pub struct PendingTxSession {
    pending_transaction_queue: Arc<Mutex<ShardedPendingTransactionQueue>>,
    shard_uid: ShardUId,
    session_access_key_tx_counts: HashMap<AccountId, usize>,
    session_deploy_tx_counts: HashMap<AccountId, usize>,
    session_gas_key_withdrawals: HashMap<(AccountId, PublicKey), Balance>,
}

impl PendingTxSession {
    pub fn new(
        pending_transaction_queue: Arc<Mutex<ShardedPendingTransactionQueue>>,
        shard_uid: ShardUId,
    ) -> Self {
        Self {
            pending_transaction_queue,
            shard_uid,
            session_access_key_tx_counts: HashMap::new(),
            session_deploy_tx_counts: HashMap::new(),
            session_gas_key_withdrawals: HashMap::new(),
        }
    }

```

**File:** nearcore/src/config.rs (L449-454)
```rust
    /// If true, SPICE nodes track uncertified transactions in a pending
    /// transaction queue to enforce P_MAX, nonce, gas-key, and deploy
    /// constraints during chunk production and RPC validation. Disabled by
    /// default; only meaningful when SPICE is active.
    #[cfg(feature = "protocol_feature_spice")]
    pub spice_pending_transaction_queue_enabled: bool,
```
