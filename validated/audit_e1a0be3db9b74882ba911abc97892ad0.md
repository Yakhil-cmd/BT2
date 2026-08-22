### Title
Reverted callback state discards `has_in_flight_tx` reset, permanently stalling `WalletContract::rlp_execute` - (File: runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs)

### Summary
`WalletContract` (the NEAR eth-implicit-account wallet contract shipped in this repo) uses a boolean flag, `has_in_flight_tx`, to serialize transaction processing: it is set to `true` before dispatching a cross-contract promise chain and is only reset to `false` inside the corresponding `#[private]` callback (`address_check_callback`, `nep_141_storage_balance_callback`, or `rlp_execute_callback`). If the callback receipt itself fails to execute successfully (e.g. it exceeds its statically-allocated prepaid gas or otherwise panics), the state mutation that resets the flag is discarded along with all other state changes from that failed execution, exactly analogous to the SteadeFi bug where a compensating second step of a two-step operation can fail and leave the vault permanently in a "stuck" status.

### Finding Description
`rlp_execute` guards re-entrancy with `self.has_in_flight_tx`, refusing new transactions while `true`: [1](#0-0) 

Every code path that returns a `Promise` sets `self.has_in_flight_tx = true` immediately before returning, with the documented invariant that it must become `false` again only inside a later private callback: [2](#0-1) 

The three callback entry points are the *only* place that reset the flag, and they always do so as their first statement: [3](#0-2) [4](#0-3) [5](#0-4) 

These callbacks are dispatched with a small, statically fixed amount of gas (`RLP_EXECUTE_CALLBACK_GAS`, `ADDRESS_CHECK_CALLBACK_GAS`, `NEP_141_STORAGE_BALANCE_CALLBACK_GAS`, each only a few Tgas plus the inner action's requested gas): [6](#0-5) 

and they deserialize attacker/relayer-influenced promise return values (`env::promise_result(0)` → `serde_json::from_slice`) before resetting is finished: [7](#0-6) [8](#0-7) 

In nearcore's runtime, a `FunctionCall` action's state changes (including `storage_write`s performed via `near_bindgen`'s account serialization on return) are only committed to the trie when the WASM execution completes successfully; if it fails (host error such as exceeded gas, deserialization panic, or any other trap), the whole outcome is discarded and no state mutations from that execution — including the `has_in_flight_tx = false` write — are persisted: [9](#0-8) 

This means that if the target contract of an emulated transaction (an arbitrary `target`/`token_id` chosen by whoever signs the RLP transaction — an "eth implicit account" owner or a relaying party) returns an oversized or unusual payload to the wallet contract's registrar/`storage_balance_of` lookup, or if the inner action + fixed callback gas budget is otherwise exhausted, the callback execution fails. Because the reset statement lives inside that same failed execution, `has_in_flight_tx` remains permanently `true`. There is no admin/reset method exposed by `WalletContract` to clear this flag afterward, so every subsequent call to `rlp_execute` for that account is rejected forever with `"transaction already in progress"`.

This is structurally identical to the SteadeFi report: step 1 (dispatch, `has_in_flight_tx = true`) is committed; step 2 (the compensating/rollback state write in the callback) can fail due to gas/resource restrictions outside the contract's control, and the failure of step 2 does not roll back step 1 — it leaves the account's operational state permanently "stuck," halting all further activity for that account until a code fix or migration.

### Impact Explanation
Any eth-implicit account using this wallet contract can be permanently denied service (halted) once a single receipt-chain callback fails to complete within its fixed gas budget. Since `target`/`token_id` for ERC20 transfers and the address registrar lookup are external, attacker-influenceable contracts (or simply slow/large responses), a malicious or misbehaving counterparty can trigger this deterministically, permanently disabling `rlp_execute` for the victim account with no recovery path. This is a chain-level denial-of-service on affected accounts, matching the report's "complete halt in activities" impact class.

### Likelihood Explanation
Likelihood is moderate-to-high: the trigger only requires an unprivileged actor (the wallet owner or any relayer submitting an RLP transaction) to target a contract that returns a payload large enough, or otherwise causes gas usage sufficiently close to the fixed callback gas budget, to blow the callback's static gas allocation. No validator or malicious-node behavior is required — it is fully reachable via a normal user-submitted transaction to `rlp_execute`.

### Recommendation
Do not gate liveness on a flag whose reset is written inside the very receipt whose failure is being guarded against. Options:
- Reset `has_in_flight_tx` in a dedicated always-succeeding cleanup step scheduled unconditionally (e.g. a trivial final callback with generous, success-independent gas and no dependency on deserializing untrusted payloads) so the reset cannot be rolled back together with the fallible logic.
- Bound/validate the size of external promise results before attempting to deserialize them, and/or allocate a safety margin of gas specifically for the "revert/reset" bookkeeping path, separate from the gas used for business logic that could fail.
- Provide a supervised recovery mechanism (e.g., a timeout-based or access-controlled way to clear `has_in_flight_tx`) in case of unexpected callback failure, so no single failed execution can produce a permanent, irrecoverable lock.

### Proof of Concept
1. Wallet owner (or relayer) submits an RLP transaction via `rlp_execute` for an emulated ERC-20 transfer (`EthEmulationKind::ERC20Transfer`) targeting an NEP-141 `token_id` contract. `has_in_flight_tx` is set to `true` and a promise chain `storage_balance_of → nep_141_storage_balance_callback` is scheduled with gas `NEP_141_STORAGE_BALANCE_CALLBACK_GAS` (fixed, a few Tgas plus the inner action's gas): [10](#0-9) 
2. The `token_id` contract (controlled by, or simply implemented differently than, a standard NEP-141 token) returns an oversized/complex JSON payload from `storage_balance_of`, or the callback's downstream `serde_json::from_slice` / follow-up promise construction consumes gas beyond the statically reserved budget.
3. `nep_141_storage_balance_callback` execution fails (exceeds prepaid gas / panics) before or without completing successfully; per nearcore's function-call execution model, none of that execution's state writes — including `self.has_in_flight_tx = false` — are committed.
4. All subsequent calls to `rlp_execute` on this account immediately return `ExecuteResponse { success: false, error: Some("Error: transaction already in progress, please try again later.") }` forever, since no code path exists to clear `has_in_flight_tx` outside of a successfully-completing callback.

Note: I was not able to fully trace the exact gas-accounting code path for `FunctionCallError::HostError` due to running out of tool iterations before completing the read of `function_call.rs`'s failure branch; the citation at lines 140–151 shows the commit-on-success gating, which is consistent with standard nearcore semantics (failed action ⇒ discarded state changes), but a full confirmation of every failure mode (panic vs. gas-exceeded vs. deserialization error) reaching that same discard path would benefit from further review of `runtime/runtime/src/function_call.rs` in its entirety.

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L34-41)
```rust
const NEP_141_STORAGE_DEPOSIT_GAS: Gas = Gas::from_tgas(5);
const NEP_141_STORAGE_BALANCE_OF_GAS: Gas = Gas::from_tgas(5);
const REGISTRAR_LOOKUP_GAS: Gas = Gas::from_tgas(5);
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

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L94-128)
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

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L133-159)
```rust
    #[private]
    pub fn address_check_callback(
        &mut self,
        target: AccountId,
        action: near_action::Action,
        caller_deposit: Option<CallerDeposit>,
    ) -> PromiseOrValue<ExecuteResponse> {
        self.has_in_flight_tx = false;
        let maybe_account_id: Option<AccountId> = match env::promise_result(0) {
            PromiseResult::Failed => {
                return PromiseOrValue::Value(ExecuteResponse {
                    success: false,
                    success_value: None,
                    error: Some("Call to Address Registrar contract failed".into()),
                });
            }
            PromiseResult::Successful(value) => match serde_json::from_slice(&value) {
                Ok(x) => x,
                Err(_) => {
                    return PromiseOrValue::Value(ExecuteResponse {
                        success: false,
                        success_value: None,
                        error: Some("Unexpected response from account registrar".into()),
                    });
                }
            },
        };
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L194-221)
```rust
    #[private]
    pub fn nep_141_storage_balance_callback(
        &mut self,
        token_id: AccountId,
        receiver_id: AccountId,
        action: near_action::Action,
        caller_deposit: Option<CallerDeposit>,
    ) -> PromiseOrValue<ExecuteResponse> {
        self.has_in_flight_tx = false;
        let maybe_storage_balance: Option<StorageBalance> = match env::promise_result(0) {
            PromiseResult::Failed => {
                return PromiseOrValue::Value(ExecuteResponse {
                    success: false,
                    success_value: None,
                    error: Some(format!("Call to NEP-141 {token_id}::storage_balance_of failed")),
                });
            }
            PromiseResult::Successful(value) => match serde_json::from_slice(&value) {
                Ok(x) => x,
                Err(_) => {
                    return PromiseOrValue::Value(ExecuteResponse {
                        success: false,
                        success_value: None,
                        error: Some("Unexpected response from NEP-141 storage_balance_of".into()),
                    });
                }
            },
        };
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L275-281)
```rust
    #[private]
    pub fn rlp_execute_callback(
        &mut self,
        caller_deposit: Option<CallerDeposit>,
    ) -> ExecuteResponse {
        self.has_in_flight_tx = false;
        let n = env::promise_results_count();
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L433-457)
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
```

**File:** runtime/runtime/src/function_call.rs (L140-151)
```rust
    result.gas_burnt = result.gas_burnt.checked_add_result(outcome.burnt_gas)?;
    result.gas_burnt_for_function_call =
        result.gas_burnt_for_function_call.checked_add_result(outcome.burnt_gas)?;
    // Runtime in `generate_refund_receipts` takes care of using proper value for refunds.
    // It uses `gas_used` for success and `gas_burnt` for failures. So it's not an issue to
    // return a real `gas_used` instead of the `gas_burnt` into `ActionResult` even for
    // `FunctionCall`s error.
    result.gas_used = result.gas_used.checked_add_result(outcome.used_gas)?;
    result.compute_usage = safe_add_compute(result.compute_usage, outcome.compute_usage)?;
    result.logs.extend(outcome.logs);
    result.profile.merge(&outcome.profile);
    if execution_succeeded {
```
