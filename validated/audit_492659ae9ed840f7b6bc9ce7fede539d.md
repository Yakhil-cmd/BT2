### Title
Loss of assets when `DeleteAccountAction.beneficiary_id` points to a non-existent account - (File: `runtime/runtime/src/actions.rs`)

### Summary
`DeleteAccountAction` lets any account owner (or any contract via the `promise_batch_action_delete_account` host function) delete their own account and redirect the remaining balance to an arbitrary `beneficiary_id`. The protocol only validates that `beneficiary_id` is a syntactically valid `AccountId`; it never checks that the account actually exists. If the beneficiary account does not exist, the resulting balance-refund receipt fails and the whole remaining balance is permanently burned instead of being returned to the caller or the intended recipient — directly analogous to the reported Gearbox bug where a missing `to != address(0)` check let a caller's assets be irrecoverably destroyed by a parameter mistake.

### Finding Description
`action_delete_account` in `runtime/runtime/src/actions.rs` deletes the account and, if it had a positive balance, immediately queues a system-generated transfer receipt to `delete_account.beneficiary_id`: [1](#0-0) 

The only validation performed on `beneficiary_id` before this happens is a syntax check, not an existence check: [2](#0-1) 

The generated receipt is a "balance refund" with `predecessor_id = "system"`: [3](#0-2) 

When this refund receipt is later applied, if the beneficiary account does not exist, `check_transfer_to_nonexisting_account` is invoked with `implicit_account_creation_eligible = false` (because it's a refund, and refunds are explicitly excluded from implicit-account creation per the code comment), so it returns `AccountDoesNotExist` and the transfer fails: [4](#0-3) 

Crucially, when a refund receipt (`predecessor_id == "system"`) fails, the funds are not re-refunded anywhere — they are unconditionally burned: [5](#0-4) 

This burn-on-failed-refund behavior is also explicitly documented: [6](#0-5) 

Because `action_delete_account` has already set `*account = None` and removed the account from state before the beneficiary receipt executes (it's a separate, later receipt), there is no way to recover once the beneficiary-transfer receipt fails — the account is gone and the tokens are burnt. This is reachable by an ordinary unprivileged transaction (`DeleteAccount` action) or through a contract's own promise batch (`promise_batch_action_delete_account` host function): [7](#0-6) 

### Impact Explanation
A user (or a contract acting on a user's behalf) who supplies a mistyped, deleted-in-the-meantime, or otherwise non-existent `beneficiary_id` when deleting their account loses their entire remaining account balance permanently — the tokens are burned rather than returned to the signer or refunded. This is a genuine, concrete loss-of-funds condition triggered purely by a caller-supplied parameter, matching the exact bug class in the external report (irrecoverable loss of assets due to an unchecked destination parameter). Unlike a plain `Transfer` action to a non-existent account (which fails the whole transaction before the source account's balance is touched, per `test_refund_on_send_money_to_non_existent_account`), the delete-account flow has already destroyed the source account and irrevocably committed the balance to a refund receipt, so the failure mode results in a burn instead of a revert.

### Likelihood Explanation
Likelihood is high in the sense that no privileged access is required — any account holder can trigger it with a single `DeleteAccount` transaction, and it requires no cooperation from validators or other parties. It is a "mistake" scenario (typo in `beneficiary_id`, referencing a not-yet-created or already-deleted account) rather than something an attacker gains value from (the attacker/griefer does not profit — funds are burned network-wide, not stolen), so it is best framed as an unintentional/accidental loss vector rather than an economic attack, consistent with how the original Gearbox report also framed it as a self-inflicted mistake rather than external exploitation.

### Recommendation
Before generating the balance-refund receipt in `action_delete_account`, verify that `beneficiary_id` corresponds to an existing account (or restrict allowed beneficiaries to accounts that are known to exist, e.g., require the signer to have proven the account's existence, similarly to how implicit-account creation is explicitly disallowed for refunds). Alternatively, if the beneficiary account does not exist at delete time, either reject the `DeleteAccount` action outright (fail-fast, preserving the account and balance) or fall back to refunding the balance to the deleting account's original owner/predecessor instead of unconditionally burning it.

### Proof of Concept
1. Create account `alice.near` with a non-zero balance.
2. Submit a `SignedTransaction` from `alice.near` to itself containing a single `Action::DeleteAccount(DeleteAccountAction { beneficiary_id: "typo-nonexistent.near" })` (a syntactically valid but non-existent account, distinct from an eth-implicit account so no implicit-account creation applies).
3. `action_delete_account` executes: `alice.near`'s account is removed from state and a `Receipt::new_balance_refund("typo-nonexistent.near", balance)` is queued (`runtime/runtime/src/actions.rs:349-356`).
4. When that refund receipt is applied, `check_account_existence` → `check_transfer_to_nonexisting_account` returns `AccountDoesNotExist` because it's a refund receipt and implicit account creation is disabled for refunds (`runtime/runtime/src/actions.rs:829-849`).
5. Because `receipt.predecessor_id().is_system()` and the result is an error, `apply_action_receipt` adds the entire deposit to `stats.balance.other_burnt_amount` (`runtime/runtime/src/lib.rs:914-922`) — the funds are burned; `alice.near` no longer exists and no account received the balance.

### Citations

**File:** runtime/runtime/src/actions.rs (L349-356)
```rust
    // We use current amount as a pay out to beneficiary.
    let account_balance = account_ref.amount();
    if account_balance > Balance::ZERO {
        result
            .new_receipts
            .push(Receipt::new_balance_refund(&delete_account.beneficiary_id, account_balance));
    }
    let remove_result = remove_account(state_update, account_id)?;
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

**File:** runtime/runtime/src/action_validation.rs (L377-381)
```rust
fn validate_delete_action(action: &DeleteAccountAction) -> Result<(), ActionsValidationError> {
    validate_action_account_id(&action.beneficiary_id)?;

    Ok(())
}
```

**File:** core/primitives/src/receipt.rs (L496-510)
```rust
    pub fn new_balance_refund(receiver_id: &AccountId, refund: Balance) -> Self {
        Receipt::V0(ReceiptV0 {
            predecessor_id: "system".parse().unwrap(),
            receiver_id: receiver_id.clone(),
            receipt_id: CryptoHash::default(),
            receipt: ReceiptEnum::Action(ActionReceipt {
                signer_id: "system".parse().unwrap(),
                signer_public_key: PublicKey::empty(KeyType::ED25519),
                gas_price: Balance::ZERO,
                output_data_receivers: vec![],
                input_data_ids: vec![],
                actions: vec![Action::Transfer(TransferAction { deposit: refund })],
            }),
        })
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

**File:** runtime/near-vm-runner/src/logic/logic.rs (L3440-3461)
```rust
    pub fn promise_batch_action_delete_account(
        &mut self,
        promise_idx: u64,
        beneficiary_id_len: u64,
        beneficiary_id_ptr: u64,
    ) -> Result<()> {
        self.result_state.gas_counter.pay_base(base)?;
        if self.context.is_view() {
            return Err(HostError::ProhibitedInView {
                method_name: "promise_batch_action_delete_account".to_string(),
            }
            .into());
        }
        let beneficiary_id =
            self.read_and_parse_account_id(beneficiary_id_ptr, beneficiary_id_len)?;

        let (receipt_idx, sir) = self.promise_idx_to_receipt_idx_with_sir(promise_idx)?;
        self.pay_action_base(ActionCosts::delete_account, sir)?;

        self.ext.append_action_delete_account(receipt_idx, beneficiary_id);
        Ok(())
    }
```
