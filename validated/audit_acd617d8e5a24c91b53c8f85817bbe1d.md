### Title
`UseGlobalContractAction` binds an account's code permanently to a mutable, attacker-controlled `AccountId` pointer that survives full-access-key rotation, letting the original controller push malicious WASM that drains the new owner - (File: `runtime/runtime/src/global_contracts.rs`)

### Summary
The report describes a class of bug where a module/selector pointer is installed by the original controller of a smart account, is never cleared when control of the account changes hands, and later resolves to attacker-controlled code that executes with the *new* owner's storage and balance context (a delegatecall-style trust anchor that is never re-validated across an ownership change). nearcore has a directly analogous mechanism: `GlobalContractDeployMode::AccountId` + `UseGlobalContractAction`.

### Finding Description
`Action::UseGlobalContract` lets an account point its `AccountContract` field at code identified not by a hash, but by an `AccountId`: [1](#0-0) 

The comment on `GlobalContractDeployMode::AccountId` makes the mutability explicit: "This allows the owner to update the contract for all its users." [2](#0-1) 

Once an account executes `UseGlobalContractAction { contract_identifier: GlobalContractIdentifier::AccountId(deployer) }`, its `account.contract()` becomes `AccountContract::GlobalByAccount(deployer)` permanently - there is no code-hash pinning, no snapshot, and no re-consent mechanism. Any later `DeployGlobalContractAction` submitted by `deployer` with `GlobalContractDeployMode::AccountId` silently propagates new code to *every* account that ever referenced that identifier, as demonstrated in `test_global_contract_update`, where redeploying the global contract under the same `AccountId` immediately changes the behavior of function calls into the consuming accounts without those accounts taking any further action: [3](#0-2) 

The execution model itself is exactly the delegatecall pattern the report describes: the WASM bytecode comes from the referenced `AccountId`'s global contract, but `storage_read`/`storage_write` and the account balance/gas operate on the *using* account's own trie and balance (`RuntimeContractIdentifier::resolve` just swaps in the code hash while `current_account_id` stays the calling account): [4](#0-3) 

There is no hook anywhere in access-key management (`AddKey`/`DeleteKey`) that clears or re-validates this `AccountContract::GlobalByAccount` pointer when the account's controlling full-access key set changes - i.e. when the account is effectively "handed over" to a new controller (e.g. an on-chain account marketplace transfer, a smart-wallet handoff, or simple full-access-key rotation). The new controller inherits the pointer with no visible signal that the account's actual executable code is dictated by a third party who can change it at will.

### Impact Explanation
Any account that has ever executed `UseGlobalContractAction` against an `AccountId`-mode global contract remains permanently and invisibly dependent on that deployer account. If control of the *using* account changes hands (new owner takes over via full-access-key rotation, an account-sale flow, or a DAO/smart-wallet transfer), the original deployer can redeploy new WASM under the same `AccountId` identifier at any later time. Since a `FunctionCall` receipt into that account can be sent by any predecessor (no access key required for the incoming receipt) - matching the report's broad trigger surface of "any DeFi integration ... marketplace flow that calls the contract directly" - the malicious code then executes with the new owner's storage and balance, allowing it to:
- Drain the account's NEAR balance (e.g. via `Promise::transfer` baked into the redeployed contract).
- Overwrite arbitrary contract storage keys.
- Add new access keys, add/rotate keys to grant the attacker a permanent backdoor, or otherwise take further unauthorized actions from the account.

This is a concrete unauthorized state/balance change reachable purely via submitted transactions, matching the "unauthorized state or balance change" and "theft" criteria.

### Likelihood Explanation
Likelihood requires a prior `UseGlobalContractAction { AccountId(deployer) }` to have been executed against the victim account before/at handoff, and later a `DeployGlobalContractAction` redeploy by that same `deployer` id after the handoff, followed by any incoming `FunctionCall` triggering the newly deployed method. All of these are ordinary, unprivileged transaction actions available to any account - no validator or network-layer capability is required. The likelihood is highest in flows where account "ownership" is transferred by handing over/rotating full access keys (e.g. custodial-to-self-custody migrations, account marketplaces, smart-wallet resale) while the account still carries a prior `UseGlobalContractAction` reference the new owner is unaware of, since nothing in the account view (`view_account`/`view_code`) prominently flags that the account's code is dictated by another `AccountId` that can change at any time.

### Recommendation
- Require callers of `UseGlobalContractAction` (or a similarly-scoped follow-up action) to acknowledge the mutability risk by pinning to `GlobalContractDeployMode::CodeHash` for security-sensitive transfer/handoff flows, or provide an explicit "unset global contract" / re-attestation action that a new full-access-key holder must invoke to re-validate the account's `AccountId`-based code dependency.
- Consider surfacing the referencing `GlobalContractIdentifier::AccountId` prominently in account/contract views so it is not a hidden trust dependency.
- Alternatively, disallow `UseGlobalContractAction` from binding by mutable `AccountId` for accounts that are otherwise expected to change controllers (documented risk in `docs/RuntimeSpec/Actions.md` currently only mentions the update capability, not the ownership-handoff risk).

### Proof of Concept
1. Deployer account `D` deploys a benign global contract with `DeployGlobalContractAction { deploy_mode: AccountId }` (see `test_global_contract_update` setup): [5](#0-4) 
2. Victim account `V` (about to be transferred/sold) executes `UseGlobalContractAction { contract_identifier: AccountId(D) }`, setting `V.contract() == AccountContract::GlobalByAccount(D)`.
3. `V`'s full access keys are rotated/handed to a new owner `O` (simulating a sale/handoff) — nothing in this step touches or clears `V`'s `AccountContract`.
4. `D` submits a new `DeployGlobalContractAction { deploy_mode: AccountId }` with malicious WASM (e.g. containing a `promise_transfer` to an attacker account) under the same `AccountId` identifier, exactly as in `test_global_contract_nonce_prevents_stale_overwrite`: [6](#0-5) 
5. Any account sends a `FunctionCall` receipt to `V` invoking the malicious method; the code executes with `current_account_id == V`, draining `V`'s balance/storage under `O`'s ownership without `O`'s consent.

### Citations

**File:** runtime/runtime/src/global_contracts.rs (L93-106)
```rust
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

**File:** test-loop-tests/src/tests/global_contracts.rs (L71-106)
```rust
#[test]
fn test_global_contract_update() {
    let mut env = GlobalContractsTestEnv::setup(Balance::from_near(1000));
    let use_accounts = [env.account_shard_0.clone(), env.account_shard_1.clone()];

    env.deploy_trivial_global_contract(GlobalContractDeployMode::AccountId);

    for account in &use_accounts {
        env.use_global_contract(
            account,
            GlobalContractIdentifier::AccountId(env.deploy_account.clone()),
        );

        // Currently deployed trivial contract doesn't have any methods,
        // so we expect any function call to fail with MethodNotFound error
        let call_tx = env.call_global_contract_tx(account.clone(), account.clone());
        let call_outcome = env.execute_tx(call_tx);
        assert_matches!(
            call_outcome.status,
            FinalExecutionStatus::Failure(TxExecutionError::ActionError(ActionError {
                kind: ActionErrorKind::FunctionCallError(FunctionCallError::MethodResolveError(
                    MethodResolveError::MethodNotFound
                )),
                index: _
            }))
        );
    }

    env.deploy_global_contract(GlobalContractDeployMode::AccountId);

    for account in &use_accounts {
        // Function call should be successful after deploying rs contract
        // containing the function we call here
        env.assert_call_global_contract_success(account.clone(), account.clone());
    }
}
```

**File:** runtime/runtime/src/contract_code.rs (L36-50)
```rust
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

**File:** test-loop-tests/src/tests/global_contracts_distribution.rs (L291-299)
```rust
    // Step 2: Deploy rs_contract as second version (AccountId mode).
    // This will have a higher auto-incremented nonce.
    tracing::info!(target: "test", "Deploying second version of global contract (rs_contract)...");
    let tx = env.chunk_producer_node().tx_deploy_global_contract(
        &deploy_user,
        near_test_contracts::rs_contract().to_vec(),
        GlobalContractDeployMode::AccountId,
    );
    env.env.runner_for_account(&env.chunk_producer).run_tx(tx, Duration::seconds(5));
```
