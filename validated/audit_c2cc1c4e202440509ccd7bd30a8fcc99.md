Confirmed: `GlobalContractIdentifier::AccountId` resolution reads the code hash dynamically via `TrieKey::GlobalContractCode` ( [1](#0-0) ) at every execution, and `action_deploy_global_contract` / `use_global_contract` let the owning account redeploy under the same `AccountId` identifier at will, instantly rewriting the code that every account which previously issued a `UseGlobalContractAction` for that identifier will run on its very next call ( [2](#0-1)  and [3](#0-2) ).

### Title
Global-contract-by-`AccountId` owner can instantly rewrite shared code with no timelock, unilaterally changing behavior/fees for all referencing accounts - (File: `runtime/runtime/src/global_contracts.rs`)

### Summary
`GlobalContractDeployMode::AccountId` lets any ordinary (non-validator) account act as a "code owner" whose `DeployGlobalContractAction` instantly and unconditionally overwrites the shared code that all accounts referencing it via `UseGlobalContractAction` execute ( [4](#0-3) ). This is the direct structural analog of the Cred report: an unprivileged party unilaterally changes a shared, economically meaningful parameter (fee logic, in Cred's case; arbitrary executable code, here) affecting other unprivileged users' funds/behavior with no timelock, no notice period, and no guaranteed exit window.

### Finding Description
Once account `X` deploys code with `GlobalContractDeployMode::AccountId`, other accounts opt in by executing `UseGlobalContractAction { contract_identifier: AccountId(X) }`, which sets `AccountContract::GlobalByAccount(X)` on their own account ( [5](#0-4) ). From that point on, every `FunctionCall` executed against the referencing account resolves its code by looking up the current value stored under `TrieKey::GlobalContractCode { identifier: AccountId(X) }` at call time — there is no snapshot, no version pinning, and no per-user opt-out delay ( [6](#0-5)  and [1](#0-0) ).

The owner `X` can call `DeployGlobalContractAction` again at any later time. `initiate_distribution` simply re-derives the same `GlobalContractIdentifier::AccountId(X)`, bumps a nonce, and distributes the new code to every shard, overwriting the old code under the same identifier ( [3](#0-2) , [7](#0-6) ). Documentation explicitly confirms this is by design: "This allows the owner to update the contract for all its users" ( [8](#0-7) , [9](#0-8) ).

This mirrors the Cred bug class precisely: the "cred creator" (an unprivileged account) could instantly change `sellShareRoyalty_` and impose it retroactively on existing share holders with no timelock and no grace period to exit. Here, the global-contract owner can instantly change the *entire code* governing every account that referenced it, with the same absence of a timelock or exit window — and code changes are strictly more powerful than a fee-percentage change, since the new code fully controls what promises/transfers/state-writes are executed on the referencing account's next invocation.

### Impact Explanation
Any account that references an `AccountId`-mode global contract is fully exposed to whatever code the owner chooses to push next, with no delay to react. If the owner turns malicious (or the owner's key is compromised) after many accounts have already opted in and accumulated balance/state under that shared code, the very next `FunctionCall` any of those accounts processes will run the new, attacker-chosen logic — which can transfer the account's balance via promises, corrupt account storage, or otherwise misappropriate funds, exactly the "unauthorized state or balance change" scenario the Cred report warns about. Unlike a local contract redeploy (which only affects the deploying account itself), this single action affects every account across every shard that adopted the identifier.

### Likelihood Explanation
Reachable purely through unprivileged, submitted transactions: `DeployGlobalContractAction` (deploy/update) and `UseGlobalContractAction` (opt-in) are both ordinary actions available to any account, requiring no validator or protocol-level privilege ( [10](#0-9) ). The redeploy path performs no check against existing adopters, no delay, and no consent re-confirmation, so the likelihood of a malicious or compromised owner instantly weaponizing an update against already-onboarded accounts is directly proportional to how widely the identifier has been adopted — the same dynamic the Cred judges flagged as medium severity for lack of a timelock.

### Recommendation
Introduce a timelock/notice mechanism for `AccountId`-mode global contract updates, mirroring the report's suggested pattern: (1) require the owner to submit an update request that only becomes effective after a fixed delay (e.g., one epoch), during which referencing accounts can observe the pending code and voluntarily unlink (via `DeployContract`/re-`UseGlobalContract` to a different identifier) before it takes effect; or (2) make `AccountId`-mode adoption require an explicit, re-confirmable opt-in per update (e.g., binding the reference to a specific code hash/nonce rather than tracking the mutable `AccountId` pointer), so that an owner's future updates do not automatically propagate to existing adopters without their fresh consent.

### Proof of Concept
1. Account `X` deploys contract `V1` with `GlobalContractDeployMode::AccountId` ( [11](#0-10) ).
2. Accounts `A`, `B`, `C` each submit `UseGlobalContractAction { contract_identifier: AccountId(X) }`, setting `AccountContract::GlobalByAccount(X)` on their own accounts and accumulating balance/state while running `V1` ( [12](#0-11) ).
3. `X` submits a second `DeployGlobalContractAction` with malicious code `V2` under the same `AccountId` mode; `initiate_distribution` propagates `V2` to all shards under the same `GlobalContractIdentifier::AccountId(X)`, immediately superseding `V1` ( [13](#0-12) ).
4. The very next `FunctionCall` receipt processed against `A`, `B`, or `C` resolves to `V2` via `RuntimeContractIdentifier::resolve` ( [6](#0-5) ), executing attacker-chosen logic against each account's balance/storage with zero notice and zero opportunity for those accounts to have exited beforehand.

### Citations

**File:** runtime/runtime/src/contract_code.rs (L32-50)
```rust
impl RuntimeContractIdentifier {
    /// Resolve a contract identifier from an account's contract field.
    ///
    /// Returns `RuntimeContractIdentifier::None` if the account has no contract deployed.
    pub(crate) fn resolve(
        account_id: &AccountId,
        account_contract: AccountContract,
        state_update: &TrieUpdate,
        chain_id: &str,
        access: AccessOptions,
    ) -> Result<Self, StorageError> {
        let local_hash = match GlobalContractIdentifier::try_from(account_contract) {
            Ok(gci) => {
                let code_hash = gci.clone().hash(state_update, access)?;
                return Ok(RuntimeContractIdentifier::Global { code_hash, identifier: gci });
            }
            Err(ContractIsLocalError::NotDeployed) => return Ok(RuntimeContractIdentifier::None),
            Err(ContractIsLocalError::Deployed(local_hash)) => local_hash,
        };
```

**File:** runtime/runtime/src/contract_code.rs (L91-106)
```rust
impl GlobalContractAccessExt for GlobalContractIdentifier {
    fn hash(self, store: &TrieUpdate, access: AccessOptions) -> Result<CryptoHash, StorageError> {
        if let GlobalContractIdentifier::CodeHash(hash) = self {
            return Ok(hash);
        }
        let key = TrieKey::GlobalContractCode { identifier: self.into() };
        let value_ref =
            store.get_ref(&key, KeyLookupMode::MemOrFlatOrTrie, access)?.ok_or_else(|| {
                let TrieKey::GlobalContractCode { identifier } = key else { unreachable!() };
                StorageError::StorageInconsistentState(format!(
                    "Global contract identifier not found {:?}",
                    identifier
                ))
            })?;
        Ok(value_ref.value_hash())
    }
```

**File:** runtime/runtime/src/global_contracts.rs (L23-61)
```rust
pub(crate) fn action_deploy_global_contract(
    state_update: &mut TrieUpdate,
    account: &mut Account,
    account_id: &AccountId,
    apply_state: &ApplyState,
    deploy_contract: &DeployGlobalContractAction,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    let _span = tracing::debug_span!(target: "runtime", "action_deploy_global_contract").entered();

    let storage_cost = apply_state
        .config
        .fees
        .storage_usage_config
        .global_contract_storage_amount_per_byte
        .saturating_mul(deploy_contract.code.len() as u128);
    let Some(updated_balance) = account.amount().checked_sub(storage_cost) else {
        result.result = Err(ActionErrorKind::LackBalanceForState {
            account_id: account_id.clone(),
            amount: storage_cost,
        }
        .into());
        return Ok(());
    };
    result.tokens_burnt =
        result.tokens_burnt.checked_add(storage_cost).ok_or(IntegerOverflowError)?;
    account.set_amount(updated_balance);

    initiate_distribution(
        state_update,
        account_id.clone(),
        deploy_contract.code.clone(),
        &deploy_contract.deploy_mode,
        apply_state.shard_id,
        result,
    )?;

    Ok(())
}
```

**File:** runtime/runtime/src/global_contracts.rs (L63-107)
```rust
pub(crate) fn action_use_global_contract(
    state_update: &mut TrieUpdate,
    account_id: &AccountId,
    account: &mut Account,
    action: &UseGlobalContractAction,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    let _span = tracing::debug_span!(target: "runtime", "action_use_global_contract").entered();
    use_global_contract(state_update, account_id, account, &action.contract_identifier, result)
}

pub(crate) fn use_global_contract(
    state_update: &mut TrieUpdate,
    account_id: &AccountId,
    account: &mut Account,
    contract_identifier: &GlobalContractIdentifier,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    let key = TrieKey::GlobalContractCode { identifier: contract_identifier.clone().into() };
    if !state_update.contains_key(&key, AccessOptions::DEFAULT)? {
        result.result = Err(ActionErrorKind::GlobalContractDoesNotExist {
            identifier: contract_identifier.clone(),
        }
        .into());
        return Ok(());
    }
    clear_account_contract_storage_usage(state_update, account_id, account)?;
    if account.contract().is_local() {
        state_update.remove(TrieKey::ContractCode { account_id: account_id.clone() });
    }
    let contract = match contract_identifier {
        GlobalContractIdentifier::CodeHash(code_hash) => AccountContract::Global(*code_hash),
        GlobalContractIdentifier::AccountId(id) => AccountContract::GlobalByAccount(id.clone()),
    };
    account.set_storage_usage(
        account.storage_usage().checked_add(contract_identifier.len() as u64).ok_or_else(|| {
            StorageError::StorageInconsistentState(format!(
                "Storage usage integer overflow for account {}",
                account_id
            ))
        })?,
    );
    account.set_contract(contract);
    Ok(())
}
```

**File:** runtime/runtime/src/global_contracts.rs (L141-233)
```rust
fn initiate_distribution(
    state_update: &mut TrieUpdate,
    account_id: AccountId,
    contract_code: Arc<[u8]>,
    deploy_mode: &GlobalContractDeployMode,
    current_shard_id: ShardId,
    result: &mut ActionResult,
) -> Result<(), RuntimeError> {
    let id = match deploy_mode {
        GlobalContractDeployMode::CodeHash => {
            GlobalContractIdentifier::CodeHash(hash(&contract_code))
        }
        GlobalContractDeployMode::AccountId => {
            GlobalContractIdentifier::AccountId(account_id.clone())
        }
    };
    // Increment the nonce and write it to state immediately to prevent multiple
    // distributions with the same nonce from being initiated. This requires
    // allowing the same nonce in the freshness check when applying the
    // distribution receipt.
    let nonce = increment_nonce(state_update, &id)?;
    let distribution_receipt =
        GlobalContractDistributionReceipt::new(id, current_shard_id, vec![], contract_code, nonce);
    let distribution_receipts =
        Receipt::new_global_contract_distribution(account_id, distribution_receipt);
    // No need to set receipt_id here, it will be generated as part of apply_action_receipt
    result.new_receipts.push(distribution_receipts);
    Ok(())
}

/// Increments the nonce for the given global contract identifier and writes
/// it to state immediately.
fn increment_nonce(
    state_update: &mut TrieUpdate,
    id: &GlobalContractIdentifier,
) -> Result<u64, RuntimeError> {
    let identifier: GlobalContractCodeIdentifier = id.clone().into();

    let nonce_key = TrieKey::GlobalContractNonce { identifier };
    let stored_nonce = get_nonce(state_update, &nonce_key)?;

    let new_nonce = stored_nonce.checked_add(1).ok_or_else(|| {
        RuntimeError::UnexpectedIntegerOverflow("increment_global_contract_nonce".into())
    })?;
    set_nonce(state_update, nonce_key, new_nonce);
    Ok(new_nonce)
}

fn apply_distribution_current_shard(
    receipt: &Receipt,
    global_contract_data: &GlobalContractDistributionReceipt,
    apply_state: &ApplyState,
    state_update: &mut TrieUpdate,
) -> Result<Compute, RuntimeError> {
    let identifier = match &global_contract_data.id() {
        GlobalContractIdentifier::CodeHash(hash) => GlobalContractCodeIdentifier::CodeHash(*hash),
        GlobalContractIdentifier::AccountId(account_id) => {
            GlobalContractCodeIdentifier::AccountId(account_id.clone())
        }
    };

    let is_nonce_fresh = check_and_update_nonce(global_contract_data, &identifier, state_update)?;
    if !is_nonce_fresh {
        return Ok(0);
    }

    let config = apply_state.config.wasm_config.clone();
    let trie_key = TrieKey::GlobalContractCode { identifier };
    let code_len = global_contract_data.code().len() as u64;
    state_update.set(trie_key, global_contract_data.code().to_vec());
    state_update.commit(StateChangeCause::ReceiptProcessing { receipt_hash: receipt.get_hash() });
    let code_hash = match global_contract_data.id() {
        GlobalContractIdentifier::CodeHash(hash) => Some(*hash),
        GlobalContractIdentifier::AccountId(_) => None,
    };
    precompile_contract_with_warming(
        &ContractCode::new(global_contract_data.code().to_vec(), code_hash),
        config,
        apply_state.next_wasm_config.clone(),
        apply_state.cache.as_deref(),
    );
    near_vm_runner::report_metrics(apply_state.shard_id, "global_contract");
    let fees = &apply_state.config.fees;
    let per_byte_total = fees
        .deploy_global_contract_execution_per_byte
        .checked_mul(code_len)
        .ok_or(IntegerOverflowError)?;
    let compute = fees
        .deploy_global_contract_execution_base
        .checked_add(per_byte_total)
        .ok_or(IntegerOverflowError)?;
    Ok(compute)
}
```

**File:** core/primitives/src/action/mod.rs (L133-142)
```rust
pub enum GlobalContractDeployMode {
    /// Contract is deployed under its code hash.
    /// Users will be able reference it by that hash.
    /// This effectively makes the contract immutable.
    CodeHash,
    /// Contract is deployed under the owner account id.
    /// Users will be able reference it by that account id.
    /// This allows the owner to update the contract for all its users.
    AccountId,
}
```

**File:** docs/RuntimeSpec/Actions.md (L444-448)
```markdown
    CodeHash,
    /// Contract is deployed under the owner account id.
    /// Users will be able reference it by that account id.
    /// This allows the owner to update the contract for all its users.
    AccountId,
```

**File:** runtime/runtime/src/lib.rs (L580-615)
```rust
            Action::DeployContract(deploy_contract) => {
                metrics::ACTION_CALLED_COUNT.deploy_contract.inc();
                action_deploy_contract(
                    state_update,
                    account.as_mut().expect(EXPECT_ACCOUNT_EXISTS),
                    account_id,
                    deploy_contract,
                    Arc::clone(&apply_state.config.wasm_config),
                    apply_state.next_wasm_config.clone(),
                    apply_state.cache.as_deref(),
                )?;
                near_vm_runner::report_metrics(apply_state.shard_id, "deploy");
            }
            Action::DeployGlobalContract(deploy_global_contract) => {
                metrics::ACTION_CALLED_COUNT.deploy_global_contract.inc();
                let account = account.as_mut().expect(EXPECT_ACCOUNT_EXISTS);
                action_deploy_global_contract(
                    state_update,
                    account,
                    account_id,
                    apply_state,
                    deploy_global_contract,
                    &mut result,
                )?;
            }
            Action::UseGlobalContract(use_global_contract) => {
                metrics::ACTION_CALLED_COUNT.use_global_contract.inc();
                let account = account.as_mut().expect(EXPECT_ACCOUNT_EXISTS);
                action_use_global_contract(
                    state_update,
                    account_id,
                    account,
                    use_global_contract,
                    &mut result,
                )?;
            }
```
