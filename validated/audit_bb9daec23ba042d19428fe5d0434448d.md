### Title
`WalletContract.rlp_execute` permanently bricks the wallet if `ban_relayer`'s `DeleteKey` sub-action fails - (File: `runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs`)

### Summary
The `near-wallet-contract` (the eth-implicit-account wallet used to emulate Ethereum accounts on NEAR) uses a boolean `has_in_flight_tx` flag to serialize transaction processing, exactly like the DAO's `_userHasActiveProposal` mapping. The flag is set to `true` before a promise is dispatched and is only reset to `false` inside specific downstream callback/action handlers. One of the paths that is supposed to reset it — `ban_relayer` — is bundled as the *second* action of a two-action batch receipt whose *first* action (`delete_key`) can fail. NEAR's receipt-processing loop aborts remaining actions in a receipt as soon as one action fails, so if `delete_key` fails, `ban_relayer` never runs and `has_in_flight_tx` is stuck at `true` forever, permanently locking the wallet contract out of all future `rlp_execute` calls — the same class of "unhandled failure blocks a required finalization step" bug as the Solidity `DAO._executeApproval` finding.

### Finding Description
`has_in_flight_tx` is treated as a mutex guarding `rlp_execute`: [1](#0-0) 

It is set to `true` right before returning a promise in three places, including the "faulty relayer" branch: [2](#0-1) 

The promise created for that branch, `create_ban_relayer_promise`, batches **two actions into a single receipt** sent to the wallet's own account: `delete_key(pk)` followed by `function_call_weight("ban_relayer", ...)`: [3](#0-2) 

`ban_relayer` is the only handler in this code path that resets the flag: [4](#0-3) 

The runtime processes actions within one `ActionReceipt` sequentially and **stops processing subsequent actions as soon as one action fails** (mirroring the Solidity bug's "later step never runs after the call reverts"): [5](#0-4) 

If `delete_key(pk)` fails — which the protocol supports as an explicit, named error condition for deleting a non-existent access key (`DeleteKeyDoesNotExist`, found in `core/primitives/src/errors.rs`) — the loop breaks at index 0 and the `function_call_weight("ban_relayer", ...)` action (index 1) is never executed. Because `self.has_in_flight_tx = true` was already committed by the *originating* `rlp_execute`/`address_check_callback` call (a separate, already-finalized receipt), and the only reset (`ban_relayer`) never runs, the flag remains `true` permanently.

`delete_key(pk)` can plausibly fail in practice: `pk` is `env::signer_account_pk()` of the relayer whose access key is being revoked for misbehaving. If that same access key is deleted by another actor (e.g., the account owner revoking a suspicious relayer key via an ordinary `DeleteKey` transaction, or a second relayer/owner action) in a block that lands before the `ban_relayer` receipt is applied, `delete_key(pk)` in the `ban_relayer` batch will hit `DeleteKeyDoesNotExist` and abort the receipt before `ban_relayer` runs.

This is the same bug class as the audited Solidity `DAO._executeApproval`: a state flag/gate that is supposed to be cleared unconditionally after an operation is instead gated behind an external/second action that can revert or fail, leaving the flag stuck and blocking the legitimate account holder from any further use of the contract.

### Impact Explanation
Once `has_in_flight_tx` is stuck `true`, `rlp_execute` (the sole entry point for using the eth-wallet-contract) will unconditionally return an error for every future call, for that account, forever: [6](#0-5) 

There is no other method exposed on `WalletContract` that clears `has_in_flight_tx` (`get_nonce` is read-only; every mutator that clears the flag is reached only via a promise chain the contract itself controls). The wallet-contract account becomes permanently unusable through the eth-emulation flow — a genuine denial of service against an unprivileged user's own account, reachable purely through normal transaction/receipt processing (no validator or malicious-node behavior required).

### Likelihood Explanation
This requires a specific race: the same public key that a relayer used to sign a bad transaction must be deleted (e.g. by the account owner revoking access, or a competing relayer/administrative action) between the `rlp_execute`/`address_check_callback` receipt committing `has_in_flight_tx = true` and the follow-up `ban_relayer` batch receipt being applied. This is a narrow but realistic window (access-key revocation is an expected operational action for an account owner reacting to a misbehaving relayer), and once triggered it is irreversible from the contract's own logic. I could not fully verify from the indexed code the exact default access-key provisioning model for eth-implicit accounts (i.e., whether an owner-controlled full-access key always exists to perform the competing `DeleteKey`), so likelihood should be validated further against the account-creation/key-provisioning code for eth-implicit accounts, which was not found in the indexed portion of the repo.

### Recommendation
Do not rely on a second action in the same batch receipt (or any subsequent step) to reset `has_in_flight_tx`. Reset the flag unconditionally in the same action/step that first commits it to `true`, or make `ban_relayer` independent of whether `delete_key` succeeds (e.g. issue `delete_key` and the flag-clearing `function_call` as two *separate* `.then()`-chained receipts rather than two actions in one batch, so a failure in `delete_key` does not prevent the flag-clearing call, matching the recommended `try/catch`-style mitigation from the referenced report). Alternatively, add a maintenance/recovery method (callable by the account owner) that can force-reset `has_in_flight_tx` if a promise chain terminates without clearing it.

### Proof of Concept
Conceptual reproduction (exact test harness would need to be built against `runtime/near-wallet-contract/implementation/wallet-contract/src/tests`):
1. Deploy `WalletContract` on an eth-implicit account; add a `FunctionCallPermission` access key `pk_R` for a relayer restricted to `rlp_execute`.
2. Relayer submits an `rlp_execute` transaction whose parsed action results in `Err(Error::Relayer(_))` while `signer_account_id() == current_account_id` — this hits the branch that calls `create_ban_relayer_promise(current_account_id)` and sets `has_in_flight_tx = true` for this receipt.
3. Before the resulting `ban_relayer` batch receipt (`delete_key(pk_R)` + `function_call(ban_relayer)`) is applied, submit (from any account holding a full-access key on the wallet, e.g. the owner revoking `pk_R`) a `DeleteKey(pk_R)` transaction that lands first.
4. When the `ban_relayer` batch executes, `delete_key(pk_R)` fails with `DeleteKeyDoesNotExist`; per `apply_action_receipt`'s action loop (`runtime/runtime/src/lib.rs:833-873`), processing stops and `function_call(ban_relayer)` never executes.
5. Any subsequent `rlp_execute` call on this account now unconditionally returns `"Error: transaction already in progress, please try again later."` forever, since `has_in_flight_tx` remains `true` and no other method clears it.

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L94-105)
```rust
        // To ensure user actions are executed in the desired order,
        // having multiple transactions in flight at the same time is
        // not allowed.
        if self.has_in_flight_tx {
            return PromiseOrValue::Value(ExecuteResponse {
                success: false,
                success_value: None,
                error: Some(
                    "Error: transaction already in progress, please try again later.".into(),
                ),
            });
        }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L116-128)
```rust
        match result {
            Ok(promise) => {
                self.has_in_flight_tx = true;
                PromiseOrValue::Promise(promise)
            }
            Err(Error::Relayer(_)) if env::signer_account_id() == current_account_id => {
                let promise = create_ban_relayer_promise(current_account_id);
                self.has_in_flight_tx = true;
                PromiseOrValue::Promise(promise)
            }
            Err(e) => PromiseOrValue::Value(e.into()),
        }
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L319-327)
```rust
    #[private]
    pub fn ban_relayer(&mut self) -> ExecuteResponse {
        self.has_in_flight_tx = false;
        ExecuteResponse {
            success: false,
            success_value: None,
            error: Some("Error: faulty relayer".into()),
        }
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L503-512)
```rust
fn create_ban_relayer_promise(current_account_id: AccountId) -> Promise {
    let pk = env::signer_account_pk();
    Promise::new(current_account_id).delete_key(pk).function_call_weight(
        "ban_relayer".into(),
        Vec::new(),
        NearToken::from_yoctonear(0),
        Gas::from_tgas(1),
        GasWeight(1),
    )
}
```

**File:** runtime/runtime/src/lib.rs (L833-873)
```rust
        // Executing actions one by one
        for (action_index, action) in action_receipt.actions().iter().enumerate() {
            let action_hash = create_action_hash_from_receipt_id(
                receipt.receipt_id(),
                apply_state.block_height,
                action_index,
            );
            let mut new_result = self.apply_action(
                action,
                state_update,
                apply_state,
                preparation_pipeline,
                &mut account,
                &mut actor_id,
                receipt,
                &action_receipt,
                Arc::clone(&promise_results),
                &action_hash,
                action_index,
                &action_receipt.actions(),
                epoch_info_provider,
            )?;
            if new_result.result.is_ok() {
                if let Err(e) = new_result.new_receipts.iter().try_for_each(|receipt| {
                    validate_receipt(
                        &apply_state.config.wasm_config.limit_config,
                        receipt,
                        apply_state.current_protocol_version,
                        ValidateReceiptMode::NewReceipt,
                    )
                }) {
                    new_result.result = Err(ActionErrorKind::NewReceiptValidationError(e).into());
                }
            }
            result.merge(new_result)?;
            // TODO storage error
            if let Err(ref mut res) = result.result {
                res.index = Some(action_index as u64);
                break;
            }
        }
```
