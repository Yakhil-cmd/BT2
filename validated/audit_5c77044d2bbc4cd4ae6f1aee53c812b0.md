Based on my investigation, I found a valid analog in the `near-wallet-contract`, which mirrors the "unhandled revert locks all access" bug class.

### Title
Wallet Contract permanently locks out further transactions if a promise callback panics after `has_in_flight_tx` is set - (File: `runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs`)

### Summary
The `WalletContract` (an eth-implicit account wrapper used to relay Ethereum-style transactions into Near actions) uses a single boolean flag, `has_in_flight_tx`, to enforce that only one transaction can be in flight at a time [1](#0-0) . Just like the Chainlink price feed which is queried directly and has no recovery path if the external call reverts, this flag is only cleared inside the promise callbacks (`address_check_callback`, `nep_141_storage_balance_callback`, `rlp_execute_callback`, `ban_relayer`) and is never reset by any other, independent entry point.

### Finding Description
`rlp_execute` sets `self.has_in_flight_tx = true` before returning a `Promise` that depends on one or more cross-contract calls (to the address registrar or to a NEP-141 token contract) [2](#0-1) . The flag is only ever cleared at the very start of the subsequent callback functions, e.g. `self.has_in_flight_tx = false;` in `address_check_callback`, `nep_141_storage_balance_callback`, and `rlp_execute_callback` [3](#0-2) , [4](#0-3) , [5](#0-4) .

On Near, if a contract function call aborts (panics, runs out of the attached callback gas, or hits any other execution error), all state writes made during that call — including the `has_in_flight_tx = false` write at the top of the function — are rolled back; only the state from before the call is persisted. The callback gas budgets are hard-coded constants (`RLP_EXECUTE_CALLBACK_GAS`, `ADDRESS_CHECK_CALLBACK_GAS`, `NEP_141_STORAGE_BALANCE_CALLBACK_GAS`) [6](#0-5) . Because these gas amounts are attached statically based on assumptions about the size of `action`/inputs, and because the callback also performs `serde_json` deserialization of an externally-controlled promise result, any callback execution that aborts for any reason (e.g. insufficient attached gas due to an unexpectedly large `action`/args, or any other runtime abort) leaves `has_in_flight_tx` permanently `true`. There is no public method in the contract to reset this flag: it is written only inside the `#[private]` callbacks reachable exclusively via the `.then()` continuation of the original promise chain. Once stuck, every subsequent call to `rlp_execute` is rejected with `"transaction already in progress"` [7](#0-6) , forever, exactly analogous to the Chainlink feed being permanently unreachable with no fallback and no way to reconfigure.

### Impact Explanation
Any eth-implicit account backed by this Wallet Contract can be permanently denied service (unable to submit any further Ethereum-emulated or native Near actions through `rlp_execute`) if a single in-flight promise callback ever aborts, because there is no mechanism, owner-controlled or otherwise, to clear `has_in_flight_tx`. This is a full, unrecoverable loss of functionality for the affected account, matching the "permanent denial of service" impact class of the original finding, though (unlike the price-oracle case) it is scoped to a single wallet-contract account rather than a globally shared oracle.

### Likelihood Explanation
Triggering an abort inside the callback is plausible because gas budgets for callbacks are fixed constants added on top of the user-supplied `action.gas()` [8](#0-7) , [9](#0-8) ; any underestimate of how much gas the intervening deserialization/logic needs (or a target contract returning an unexpectedly large `PromiseResult::Successful` payload that is expensive to `serde_json::from_slice`) can exhaust the attached gas and abort the callback before `has_in_flight_tx` is reset, and this can be triggered by an ordinary relayer/target contract without needing any privileged/validator access.

### Recommendation
Do not gate the reset of `has_in_flight_tx` solely on successful completion of a private callback. Options include: (1) reserving a fixed minimum gas overhead sufficiently larger than worst-case deserialization/logic cost so callbacks cannot realistically abort from gas exhaustion, (2) wrapping risky deserialization logic so it degrades gracefully rather than aborting, and (3) adding a safe, permissionless "unstick" path (e.g., a time-boxed self-call or a check based on `promise_yield`/timeout) that can clear a stale `has_in_flight_tx` flag if no callback resolves within a bounded number of blocks, so a single failed cross-contract call cannot permanently lock the account.

### Proof of Concept
1. Deploy a `WalletContract` for an eth-implicit account.
2. Submit an RLP-encoded ERC-20 transfer transaction via `rlp_execute` targeting a NEP-141 token whose `storage_balance_of` view returns an unexpectedly large/complex JSON payload, or attach the minimum viable gas such that `NEP_141_STORAGE_BALANCE_CALLBACK_GAS` is only barely sufficient under normal conditions.
3. Cause `nep_141_storage_balance_callback` to abort (e.g., via gas exhaustion from deserializing the returned payload) after `has_in_flight_tx` was already set to `true` by the preceding `rlp_execute` call [10](#0-9) .
4. Because the callback aborted, its state changes (including `has_in_flight_tx = false`) are rolled back, leaving `has_in_flight_tx == true` in persisted state.
5. Any subsequent call to `rlp_execute` now returns `"Error: transaction already in progress, please try again later."` permanently [7](#0-6) , with no way to recover the account's ability to transact.

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L37-41)
```rust
const RLP_EXECUTE_CALLBACK_GAS: Gas = Gas::from_tgas(5);
const ADDRESS_CHECK_CALLBACK_GAS: Gas = Gas::from_tgas(5).saturating_add(RLP_EXECUTE_CALLBACK_GAS);
const NEP_141_STORAGE_BALANCE_CALLBACK_GAS: Gas = Gas::from_tgas(5)
    .saturating_add(NEP_141_STORAGE_DEPOSIT_GAS)
    .saturating_add(RLP_EXECUTE_CALLBACK_GAS);
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L46-55)
```rust
pub struct WalletContract {
    pub nonce: u64,
    /// Tracks whether a transaction is currently being executed
    /// (i.e. has receipts that have not yet resolved).
    /// Invariant: `has_in_flight_tx` must be `true` when a mutable method
    /// of this contract returns a promise and `false` otherwise (except
    /// for the check if a transaction is already in flight at the beginning
    /// of `rlp_execute`).
    pub has_in_flight_tx: bool,
}
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L97-105)
```rust
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

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L106-128)
```rust
        let current_account_id = env::current_account_id();
        let predecessor_account_id = env::predecessor_account_id();
        let result = inner_rlp_execute(
            current_account_id.clone(),
            predecessor_account_id,
            target,
            tx_bytes_b64,
            &mut self.nonce,
        );

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

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L140-141)
```rust
        self.has_in_flight_tx = false;
        let maybe_account_id: Option<AccountId> = match env::promise_result(0) {
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L202-202)
```rust
        self.has_in_flight_tx = false;
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L280-280)
```rust
        self.has_in_flight_tx = false;
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L417-418)
```rust
            let callback_gas = ADDRESS_CHECK_CALLBACK_GAS.saturating_add(action.gas());
            let ext = WalletContract::ext(current_account_id).with_static_gas(callback_gas);
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L433-458)
```rust
        TransactionKind::EthEmulation(EthEmulationKind::ERC20Transfer { receiver_id, .. }) => {
            // In the case of the emulated ERC-20 transfer, the receiving account
            // might not be registered with the NEP-141 contract (per the NEP-145)
            // storage standard. Therefore we must create a multi-step promise where
            // first we check if the receiver is registered and then if not call
            // `storage_deposit` in addition to `ft_transfer`.
            let token_id = target;
            let callback_gas = NEP_141_STORAGE_BALANCE_CALLBACK_GAS.saturating_add(action.gas());
            let ext: WalletContractExt =
                WalletContract::ext(current_account_id).with_static_gas(callback_gas);
            let storage_balance_args =
                format!(r#"{{"account_id": "{}"}}"#, receiver_id.as_str()).into_bytes();
            Promise::new(token_id.clone())
                .function_call(
                    "storage_balance_of".into(),
                    storage_balance_args,
                    NearToken::from_yoctonear(0),
                    NEP_141_STORAGE_BALANCE_OF_GAS,
                )
                .then(ext.nep_141_storage_balance_callback(
                    token_id,
                    receiver_id,
                    action,
                    caller_deposit,
                ))
        }
```
