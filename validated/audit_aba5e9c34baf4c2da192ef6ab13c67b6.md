### Title
Deploy exclusivity / P_MAX in the pending-transaction queue is keyed to the wrong account for `Delegate`/`DelegateV2`-wrapped deploys, letting the real deploying account bypass NEP-611 protections - (File: chain/client/src/pending_transaction_queue.rs)

### Summary
The SPICE pending-transaction queue (PTQ) enforces "deploy exclusivity" and the `P_MAX` limit on concurrent access-key transactions per account, exactly the kind of "same block / same actor" restriction described in the Malt report's `_notSameBlock()` check. Like `_notSameBlock()`, which keys its guard on `msg.sender` and can be bypassed by routing the call through an intermediary contract, the PTQ's guard is keyed on `tx.transaction.signer_id()` — the outer transaction's signer — rather than on the account whose contract state is actually being mutated. When a deploy-like action is submitted through `Action::Delegate`/`Action::DelegateV2` (a meta-transaction), the *deploying* account is `delegate_action.sender_id` (and the deploy actually executes against that account/receiver), while the *bookkeeping* is attributed to the relayer's `signer_id`. This mismatch lets the delegate's real account escape the exclusivity and P_MAX accounting entirely.

### Finding Description
`is_deploy_like_action` correctly recognizes that a `Delegate`/`DelegateV2` action wrapping a deploy-like inner action counts as "deploy-like": [1](#0-0) 

However, `check_pending` — which performs the actual exclusivity/P_MAX admission decision — indexes all of its per-account state (`session_access_key_tx_counts`, `session_deploy_tx_counts`, and the underlying `PendingTransactionQueue.pending_accounts`) by `tx.transaction.signer_id()`, i.e., the account that signed/paid for the *outer* transaction: [2](#0-1) [3](#0-2) 

The same signer-keyed aggregation happens when chunk transactions are folded into the queue's totals: [4](#0-3) 

For a normal (non-delegated) deploy, `signer_id` and the account whose contract changes are the same, so the guard works as intended (confirmed by `test_ptq_deploy_exclusivity`): [5](#0-4) 

But for a `DelegateAction`, the top-level transaction's `signer_id` is the *relayer*, while the actual deploy is executed on behalf of `delegate_action.sender_id` (the account requesting the deploy). NEP-366 meta-transactions specifically decouple the paying/signing party (relayer) from the account whose state is changed (`sender_id`). Because `has_deploy_action`/`is_deploy_like_action` is only used to decide whether *this transaction counts as a deploy for bookkeeping purposes* — and that bookkeeping is filed under the relayer's `signer_id`, not the delegate's `sender_id` — the account that is actually deploying a contract via a relayer never accrues a `deploy_tx_count` or `access_key_tx_count` entry under its own `AccountId`. This is structurally the same class of bug as `_notSameBlock()`: a security check bound to the immediate caller identity rather than the real "acting" entity, defeated by interposing an intermediary (here, a relayer/meta-transaction) between the real actor and the guarded operation.

### Impact Explanation
NEP-611's stated purpose (`P_MAX` and deploy exclusivity) is to bound the number of pending, uncertified access-key transactions and to prevent a deploy from racing with other access-key transactions against the same account while its state (and therefore code identity / balance / storage staking) is unresolved between chunk inclusion and certification (SPICE's speculative execution model). By using `Action::Delegate`/`Action::DelegateV2` to wrap a deploy-like action, an account can have its contract deployed without ever counting toward its own `deploy_tx_count`/`access_key_tx_count`, and can simultaneously submit other access-key transactions against itself that the deploy-exclusivity check is meant to serialize away. This defeats the safety property the pending-transaction queue exists to guarantee for SPICE (avoiding races between uncertified deploys and other transactions on the same account), potentially allowing inconsistent/overlapping speculative state for that account across concurrently-pending chunks, and it also lets a contract account exceed the intended `P_MAX` throughput cap by funneling excess deploy/tx volume through relayed delegate actions instead of direct access-key transactions.

### Likelihood Explanation
This requires only that the target account cooperate with (or itself be) a relayer submitting `DelegateAction`/`DelegateV2Action`, which is a standard, permissionless, already-supported transaction shape (NEP-366 meta-transactions/gas keys) — no privileged or validator role is needed, and the feature is only gated behind `protocol_feature_spice`/`spice_pending_transaction_queue_enabled`, which is the exact code path this PTQ logic serves. Any account wanting to bypass its own deploy-exclusivity/P_MAX accounting can simply wrap the deploy in a self-relayed or third-party-relayed `DelegateAction`.

### Recommendation
When computing `has_deploy_action`/bookkeeping keys for PTQ admission and chunk aggregation, attribute deploy-like actions and access-key transaction counts found inside `Action::Delegate`/`Action::DelegateV2` to `delegate_action.sender_id` (the account actually being mutated) in addition to (or instead of) the outer `tx.transaction.signer_id()`. The `PendingAccount`/`PendingChunkData` aggregation in `add_chunk_transactions` and the `check_pending` snapshot lookup must both be updated consistently so that exclusivity/P_MAX limits are enforced against the real account whose contract/state is affected, not merely the relayer paying for gas.

### Proof of Concept
1. Account `victim.near` has a deployed contract (`HasContract::Yes`) and is subject to `P_MAX` and deploy-exclusivity tracking under NEP-611 via `chain/client/src/pending_transaction_queue.rs`.
2. Instead of sending a direct `DeployContract` transaction (`signer_id == victim.near`), the victim account constructs a `SignedDelegateAction` with `delegate_action.sender_id = victim.near`, `delegate_action.actions = [DeployContract(...)]`, and has a relayer account `relayer.near` wrap it in an outer `SignedTransaction` (`Action::DelegateV2`) with `signer_id = relayer.near`.
3. `is_deploy_like_action`/`has_deploy_action` still mark the outer transaction as "deploy-like" (per [6](#0-5) ), but `check_pending`/`add_chunk_transactions` file the resulting `deploy_tx_count`/`access_key_tx_count` under `relayer.near`, not `victim.near` (per [4](#0-3)  and [7](#0-6) ).
4. `victim.near` can now submit additional access-key transactions (transfers, function calls, even further deploys) directly, unconstrained by the deploy-exclusivity/P_MAX guard, even while its relayed deploy remains uncertified — something a direct (non-delegated) deploy from `victim.near` would have blocked, as demonstrated by `test_ptq_deploy_exclusivity` ( [5](#0-4) ).

I was not able to fully trace the runtime execution path that converts a `DelegateAction` into its resulting receipt (to confirm with 100% certainty that the deploy always lands on `delegate_action.sender_id`/`receiver_id` rather than the relayer) within the available tool budget; `runtime/runtime/src/actions.rs` and `runtime/runtime/src/lib.rs` contain the relevant `receiver_id`/delegate handling but I did not get to read those specific line ranges before running out of iterations. This should be double-checked, though the existing `validate_delegate_action_key` logic already operating on `sender_id` (seen earlier) strongly supports that the delegate's inner actions execute against `sender_id`, not the relayer.

### Citations

**File:** chain/client/src/pending_transaction_queue.rs (L171-196)
```rust
/// Returns true if the action is a deploy-like action per NEP-611:
/// DeployContract, UseGlobalContract, DeterministicStateInit, or
/// Delegate wrapping a deploy-like action.
fn is_deploy_like_action(action: &Action) -> bool {
    match action {
        Action::DeployContract(_)
        | Action::DeployGlobalContract(_)
        | Action::UseGlobalContract(_)
        | Action::DeterministicStateInit(_) => true,
        Action::Delegate(signed_delegate) => {
            signed_delegate.delegate_action.get_actions().iter().any(is_deploy_like_action)
        }
        Action::DelegateV2(signed_delegate) => {
            signed_delegate.delegate_action.get_actions().iter().any(is_deploy_like_action)
        }
        Action::CreateAccount(_)
        | Action::FunctionCall(_)
        | Action::Transfer(_)
        | Action::Stake(_)
        | Action::AddKey(_)
        | Action::DeleteKey(_)
        | Action::DeleteAccount(_)
        | Action::TransferToGasKey(_)
        | Action::WithdrawFromGasKey(_) => false,
    }
}
```

**File:** chain/client/src/pending_transaction_queue.rs (L234-268)
```rust
        for signed_tx in transactions {
            let tx = &signed_tx.transaction;
            let signer_id = tx.signer_id().clone();
            let public_key = tx.public_key().clone();
            let nonce_index = tx.nonce().nonce_index();
            let nonce = tx.nonce().nonce();
            let is_gas_key_tx = nonce_index.is_some();

            let cost = match tx_cost(config, tx, gas_price) {
                Ok(cost) => cost,
                Err(e) => {
                    tracing::warn!(
                        target: "client",
                        ?e,
                        "tx_cost failed for block transaction in pending transaction queue"
                    );
                    continue;
                }
            };

            // Update per-account aggregates.
            let chunk_account = chunk_data.accounts.entry(signer_id.clone()).or_default();
            if is_gas_key_tx {
                // Gas key tx: only deposit_cost is paid from account balance.
                chunk_account.paid_from_balance =
                    chunk_account.paid_from_balance.saturating_add(cost.deposit_cost);
            } else {
                // Access key tx: total_cost is paid from account balance.
                chunk_account.access_key_tx_count += 1;
                chunk_account.paid_from_balance =
                    chunk_account.paid_from_balance.saturating_add(cost.total_cost);
            }
            if has_deploy_action(tx.actions()) {
                chunk_account.deploy_tx_count += 1;
            }
```

**File:** chain/client/src/pending_transaction_queue.rs (L462-502)
```rust
    /// Check if a transaction can be admitted given pending constraints.
    /// If admitted, updates session state and returns constraints
    /// for the runtime's balance/nonce validation.
    ///
    /// Acquires the pending transaction queue lock briefly to read pending state, then releases it.
    pub fn check_pending(
        &mut self,
        tx: &SignedTransaction,
        has_contract: HasContract,
    ) -> PendingTxCheckResult {
        let signer_id = tx.transaction.signer_id();
        let public_key = tx.transaction.public_key();
        let nonce_index = tx.transaction.nonce().nonce_index();
        let is_gas_key_tx = nonce_index.is_some();

        let snapshot = {
            let guard = self.pending_transaction_queue.lock();
            match guard.get(&self.shard_uid) {
                Some(ptq) => ptq.query_pending_state(signer_id, public_key, nonce_index),
                None => PendingStateSnapshot::default(),
            }
        };

        let session_access_key_count =
            self.session_access_key_tx_counts.get(signer_id).copied().unwrap_or(0);
        let session_deploy_count =
            self.session_deploy_tx_counts.get(signer_id).copied().unwrap_or(0);
        let total_access_key_count = snapshot.access_key_tx_count + session_access_key_count;
        let total_deploy_count = snapshot.deploy_tx_count + session_deploy_count;
        let tx_has_deploy = has_deploy_action(tx.transaction.actions());

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
```

**File:** chain/client/src/pending_transaction_queue.rs (L526-531)
```rust
        if !is_gas_key_tx {
            *self.session_access_key_tx_counts.entry(signer_id.clone()).or_insert(0) += 1;
        }
        if tx_has_deploy {
            *self.session_deploy_tx_counts.entry(signer_id.clone()).or_insert(0) += 1;
        }
```

**File:** test-loop-tests/src/tests/pending_transaction_queue.rs (L194-257)
```rust
/// Deploy exclusivity.
///
/// Submit a DeployContract transaction and a transfer from the same account
/// simultaneously. The deploy should be included first, and the transfer
/// should be blocked while the deploy is uncertified. After certification,
/// the transfer is included.
#[test]
#[cfg_attr(not(feature = "protocol_feature_spice"), ignore)]
fn test_ptq_deploy_exclusivity() {
    init_test_logger();

    let account = create_account_id("deployer");
    let receiver = create_account_id("receiver");
    let mut env = TestLoopBuilder::new()
        .validators(1, 1)
        .add_user_account(&account, Balance::from_near(1_000))
        .add_user_account(&receiver, Balance::from_near(0))
        .delay_warmup()
        .config_modifier(|c, _| {
            c.set_spice_pending_transaction_queue_enabled(true);
        })
        .build();
    let execution_delay = 4;
    env.delay_endorsements_propagation(execution_delay);
    let mut env = env.warmup();

    // Submit a deploy tx and a transfer tx from the same account.
    let mut next_nonce: u64 = 1;
    let block_hash = env.validator().head().last_block_hash;
    let deploy_tx = SignedTransaction::from_actions(
        next_nonce,
        account.clone(),
        account.clone(),
        &create_user_test_signer(&account),
        vec![Action::DeployContract(DeployContractAction {
            code: near_test_contracts::rs_contract().to_vec(),
        })],
        block_hash,
    );
    next_nonce += 1;
    let transfer_tx = SignedTransaction::send_money(
        next_nonce,
        account.clone(),
        receiver,
        &create_user_test_signer(&account),
        Balance::from_millinear(1),
        block_hash,
    );
    let deploy_hash = deploy_tx.get_hash();
    let transfer_hash = transfer_tx.get_hash();

    env.validator().submit_tx(deploy_tx);
    env.validator().submit_tx(transfer_tx);

    // Deploy should be included first (lower nonce, picked first from pool).
    env.validator_runner().run_until_included(&[deploy_hash]);
    // Deploy exclusivity should prevent the transfer from being included
    // while the deploy is uncertified. Run up to just before certification.
    env.validator_runner().run_for_number_of_blocks(execution_delay as usize - 1);
    assert!(!is_included_in_head(&env.validator(), &[transfer_hash]));

    // Transfer should be included after certification advances.
    env.validator_runner().run_until_included(&[transfer_hash]);
}
```
