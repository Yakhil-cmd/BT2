## Title
Unvalidated `beneficiary_id` in `DeleteAccountAction` causes permanent token burn on typo/non-existent destination - (File: `runtime/runtime/src/action_validation.rs`, `runtime/runtime/src/actions.rs`, `runtime/runtime/src/lib.rs`)

### Summary
The ThorSwap `depositWithExpiry`/`deposit` bug lets a user send funds to an arbitrary, unvalidated vault address; if the address is wrong or non-existent the funds are unrecoverable. The direct analog in nearcore is `DeleteAccountAction`: the protocol only checks that `beneficiary_id` is a *syntactically* valid `AccountId`, never that the account actually exists or is reachable. If the account's remaining balance is sent to a beneficiary that turns out not to exist, the balance-refund receipt (which is treated as a system refund and therefore ineligible for implicit-account auto-creation) fails, and the entire remaining balance is permanently burned instead of returned to anyone.

### Finding Description
When a `DeleteAccountAction` is validated, `validate_delete_action` only calls `validate_action_account_id`, which merely enforces NEAR's `AccountId::validate` string-format rules — it does not check that the account exists on-chain: [1](#0-0) [2](#0-1) 

During execution, `action_delete_account` unconditionally creates a balance-refund receipt to `delete_account.beneficiary_id` for the account's remaining balance, again with no existence check: [3](#0-2) 

That refund receipt is processed with `predecessor_id == "system"`, marking it as a refund (`is_refund = true`). Crucially, implicit-account auto-creation is explicitly disabled for refunds: [4](#0-3) 

So if `beneficiary_id` does not exist and is not eligible for implicit creation (e.g., it's a named account that was never created, or was deleted, or a typo), the `Transfer` action inside the refund receipt fails via `check_transfer_to_nonexisting_account`, which rejects non-implicit-eligible transfers to nonexistent accounts: [5](#0-4) 

When that refund fails, the protocol does not retry or bounce the funds back to the deleted account's original owner — it burns them outright: [6](#0-5) 

This is documented as expected behavior ("If the execution of a refund fails, the refund amount is burnt"), confirming the root cause is a deliberate design choice, not a bug in refund plumbing — but it means the *only* safeguard against loss is the caller supplying a valid, existing `beneficiary_id`, exactly the same gap as the ThorSwap vault address issue: [7](#0-6) 

### Impact Explanation
Any account owner who submits a `DeleteAccountAction` (directly via `SignedTransaction`, via a contract's `promise_batch_action_delete_account`, or via a meta-transaction) with an incorrect, non-existent, or unreachable `beneficiary_id` permanently loses their account's entire remaining NEAR balance — the tokens are burned from circulation with no path to recovery. This matches the "concrete token... loss" and "unauthorized state or balance change" criteria: user funds are destroyed due to insufficient validation of a user-supplied destination identifier, precisely mirroring the ThorSwap vault-address analog.

### Likelihood Explanation
This requires only an ordinary, unprivileged transaction from any account holder — no validator or node privileges are needed. The scenario is realistic: a mistyped account ID, an account that was deleted between key generation and use, or a beneficiary account that a wallet/relayer failed to pre-verify would all trigger this. Given `DeleteAccountAction` is a commonly exposed wallet/contract operation, the likelihood of accidental fund loss is non-trivial, though it requires user/integrator error rather than being independently exploitable for profit by an attacker against a third party (an attacker cannot force someone else's beneficiary_id).

### Recommendation
Before generating the balance-refund receipt in `action_delete_account`, or before finalizing acceptance of the `DeleteAccountAction`, check `beneficiary_id` for actual account existence in state (not just format validity), and reject the action (returning an `ActionError`) if the beneficiary account does not exist and is not implicit-creation eligible. Alternatively, allow the refund receipt to fall back to implicit-account creation semantics even when `is_refund` is true for this specific case, so a valid implicit `beneficiary_id` still results in fund preservation rather than mandating pre-existing accounts only.

### Proof of Concept
1. Create account `alice.near` with a positive balance.
2. Submit `SignedTransaction` from `alice.near` to itself containing a single `Action::DeleteAccount(DeleteAccountAction { beneficiary_id: "nonexistent.near".parse().unwrap() })`, where `nonexistent.near` is a validly formatted but never-created account.
3. Observe: `alice.near` is deleted, a system refund receipt with a `Transfer` action targeting `nonexistent.near` is generated per [3](#0-2) .
4. That transfer fails `check_transfer_to_nonexisting_account` (implicit creation disabled for refunds) per [4](#0-3)  and [5](#0-4) .
5. The refund is recorded as burnt per [6](#0-5) , and `alice.near`'s entire balance is irrecoverably lost. This is consistent with `test_refund_on_send_money_to_non_existent_account`, which exercises the same nonexistent-account transfer failure path for ordinary transfers [8](#0-7) .

### Citations

**File:** runtime/runtime/src/action_validation.rs (L377-381)
```rust
fn validate_delete_action(action: &DeleteAccountAction) -> Result<(), ActionsValidationError> {
    validate_action_account_id(&action.beneficiary_id)?;

    Ok(())
}
```

**File:** runtime/runtime/src/action_validation.rs (L461-467)
```rust
fn validate_action_account_id(account_id: &AccountId) -> Result<(), ActionsValidationError> {
    AccountId::validate(account_id.as_str()).map_err(|_| {
        ActionsValidationError::InvalidAccountId { account_id: account_id.to_string() }
    })?;

    Ok(())
}
```

**File:** runtime/runtime/src/actions.rs (L349-355)
```rust
    // We use current amount as a pay out to beneficiary.
    let account_balance = account_ref.amount();
    if account_balance > Balance::ZERO {
        result
            .new_receipts
            .push(Receipt::new_balance_refund(&delete_account.beneficiary_id, account_balance));
    }
```

**File:** runtime/runtime/src/actions.rs (L829-849)
```rust
fn check_transfer_to_nonexisting_account(
    config: &RuntimeConfig,
    account_id: &AccountId,
    implicit_account_creation_eligible: bool,
) -> Result<(), ActionError> {
    if implicit_account_creation_eligible
        && account_is_implicit(account_id, config.wasm_config.eth_implicit_accounts)
    {
        // OK. It's implicit account creation.
        // Notes:
        // - Transfer action has to be the only action in the transaction to avoid
        // abuse by hijacking this account with other public keys or contracts.
        // - Refunds don't automatically create accounts, because refunds are free and
        // we don't want some type of abuse.
        // - Account deletion with beneficiary creates a refund, so it'll not create a
        // new account.
        Ok(())
    } else {
        Err(ActionErrorKind::AccountDoesNotExist { account_id: account_id.clone() }.into())
    }
}
```

**File:** runtime/runtime/src/lib.rs (L546-561)
```rust
        let account_id = receipt.receiver_id();
        let is_refund = receipt.predecessor_id().is_system();
        let is_the_only_action = actions.len() == 1;
        let implicit_account_creation_eligible = is_the_only_action && !is_refund;

        // Account validation
        if let Err(e) = check_account_existence(
            action,
            account,
            account_id,
            &apply_state.config,
            implicit_account_creation_eligible,
        ) {
            result.result = Err(e);
            return Ok(result);
        }
```

**File:** runtime/runtime/src/lib.rs (L914-922)
```rust
        let gas_refund_result = if receipt.predecessor_id().is_system() {
            // If the refund fails tokens are burned.
            if result.result.is_err() {
                stats.balance.other_burnt_amount = safe_add_balance(
                    stats.balance.other_burnt_amount,
                    total_deposit(&action_receipt.actions())?,
                )?
            }
            GasRefundResult::default()
```

**File:** docs/RuntimeSpec/Refunds.md (L10-13)
```markdown
Refund receipts are identified by having `predecessor_id == "system"`. They are also special because they don't cost any gas to generate or execute. As a result, they also do not contribute to the block gas limit.

If the execution of a refund fails, the refund amount is burnt.
The refund receipt is an `ActionReceipt` that consists of a single action `Transfer` with the `deposit` amount of the refund.
```

**File:** integration-tests/src/tests/standard_cases/mod.rs (L726-764)
```rust
pub fn test_refund_on_send_money_to_non_existent_account(node: impl Node) {
    let account_id = &node.account_id().unwrap();
    let node_user = node.user();
    let root = node_user.get_state_root();
    let money_used = Balance::from_yoctonear(10);
    // Successful atomic transfer has the same cost as failed atomic transfer.
    let fee_helper = fee_helper(&node);
    let transfer_cost = fee_helper.transfer_cost();
    let transaction_result =
        node_user.send_money(account_id.clone(), eve_dot_alice_account(), money_used).unwrap();
    assert_eq!(
        transaction_result.status,
        FinalExecutionStatus::Failure(
            ActionError {
                index: Some(0),
                kind: ActionErrorKind::AccountDoesNotExist { account_id: eve_dot_alice_account() }
            }
            .into()
        )
    );
    assert_eq!(transaction_result.receipts_outcome.len(), 2 + extra_refund_outcomes());
    let new_root = node_user.get_state_root();
    assert_ne!(root, new_root);
    let result1 = node_user.view_account(account_id).unwrap();
    assert_eq!(
        (result1.amount, result1.locked),
        (
            TESTING_INIT_BALANCE
                .checked_sub(TESTING_INIT_STAKE)
                .unwrap()
                .checked_sub(transfer_cost)
                .unwrap(),
            TESTING_INIT_STAKE
        )
    );
    assert_eq!(node_user.get_access_key_nonce_for_signer(account_id).unwrap(), 1);
    let result2 = node_user.view_account(&eve_dot_alice_account());
    assert!(result2.is_err());
}
```
