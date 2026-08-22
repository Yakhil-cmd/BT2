Confirmed: on function-call failure, the entire receipt's state changes are rolled back via `state_update.rollback()`, and only `Ok` results are committed via `state_update.commit(...)`. [1](#0-0)  This confirms that any panic inside a `#[private]` callback (e.g. `rlp_execute_callback`) discards all state writes made in that call, including the very first line that resets `has_in_flight_tx = false`.

### Title
Wallet Contract `has_in_flight_tx` flag can become permanently stuck `true`, permanently locking the account - (File: `runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs`)

### Summary
The `WalletContract` (the production eth-implicit-account wallet contract shipped in-repo) uses a boolean flag `has_in_flight_tx` to guarantee only one outer transaction is processed at a time. The invariant documented in the struct is that the flag must be `true` exactly while a promise is outstanding and `false` otherwise. [2](#0-1)  The flag is set to `true` right before returning a promise in `rlp_execute`, [3](#0-2)  and it is reset to `false` as the very first statement of every callback (`address_check_callback`, `nep_141_storage_balance_callback`, `rlp_execute_callback`, `ban_relayer`). [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

### Finding Description
This mirrors the reported bug class exactly: an action is performed and produces an irreversible on-chain side effect (in the GMX report, the token swap; here, the underlying cross-contract action such as a token transfer or `FunctionCall`), and the "finalizing" callback that is meant to reset the contract's state machine can fail to run to completion — leaving the guard flag permanently in the "in-progress" state with no code path left to clear it.

Concretely, `rlp_execute_callback` is invoked with a hard-coded, small gas budget `RLP_EXECUTE_CALLBACK_GAS = Gas::from_tgas(5)`. [8](#0-7)  Inside that callback, on `PromiseResult::Failed` with a `caller_deposit`, the function performs additional host calls (`env::promise_batch_create` + `env::promise_batch_action_transfer`) to refund the deposit. [9](#0-8)  Because `self.has_in_flight_tx = false;` is executed first but any subsequent panic (e.g. `GasExceeded` from an underestimated static-gas budget, or any other trap) causes the whole receipt to fail, all state changes from that function call — including the reset of the flag — are discarded per the runtime's rollback semantics. [1](#0-0)  The `has_in_flight_tx=true` state written by the *previous* successful `rlp_execute` call, however, is already committed to the trie and persists. There is no other method in the contract that clears the flag; `rlp_execute` unconditionally rejects all future calls while `has_in_flight_tx` is `true`. [10](#0-9) 

This is structurally identical to the GMXCompound.sol issue: a status/guard flag is flipped to a "busy/failed" value before an operation with real side effects executes, and the code path meant to clear that flag on failure has an unhandled edge case that leaves the flag stuck, permanently disabling all further interaction (a deadlock) with no recovery mechanism available to the account owner or anyone else.

### Impact Explanation
If triggered, the wallet contract (used for eth-implicit accounts, i.e., all Ethereum-style accounts on NEAR relying on this wallet contract for `rlp_execute`) becomes permanently unable to process any further transactions — every subsequent `rlp_execute` call immediately returns the "transaction already in progress" error, with no on-chain path to reset `has_in_flight_tx`. This is a denial-of-service against the account's ability to transact, reachable purely through normal RLP-encoded transaction submission and cross-contract call semantics, without any privileged/validator role required.

### Likelihood Explanation
Likelihood depends on whether the fixed `RLP_EXECUTE_CALLBACK_GAS`/`ADDRESS_CHECK_CALLBACK_GAS`/`NEP_141_STORAGE_BALANCE_CALLBACK_GAS` budgets are always sufficient for every code path inside the corresponding callback (including the nested refund-transfer logic on the failure branch). I was not able to fully verify from the available index whether these constants are provably sufficient in all cases, or whether other panic sources exist inside these callbacks (e.g., via `ext_registrar` parsing, action-to-promise conversion, or arithmetic in `internal`/`ethabi_utils` modules) that would trigger this same rollback-before-reset issue. This uncertainty is due to index size limits on some referenced modules (`internal.rs`, `ethabi_utils.rs`, `error.rs`) which I could not fully inspect.

### Recommendation
- Ensure `has_in_flight_tx` can never remain "true" after a receipt failure that rolls back state: e.g., avoid doing further gas-consuming host calls (like the refund transfer) inside the same callback that clears the flag, or split the refund into a separate promise chained after the flag reset is guaranteed to commit.
- Add a generous/safety-margin static gas allocation for all callbacks that also perform additional cross-contract actions on their failure branch, and add tests that intentionally starve these callbacks of gas to confirm the flag is still recoverable.
- Consider adding a decoupled recovery mechanism (e.g., a time-based fallback, or deriving "in-flight" status from the existence of an actual outstanding receipt rather than solely from a boolean written by the callback itself) so a single stuck callback execution cannot permanently brick the account.

### Proof of Concept
Conceptual PoC (not fully executable without further exploration of gas costs in `internal.rs`):
1. Submit an `rlp_execute` transaction whose parsed action results in `TransactionKind::EthEmulation(EthEmulationKind::ERC20Transfer { .. })` targeting an unregistered receiver with a non-zero relayer fee, so that `inner_rlp_execute` creates a refund promise batch as well as the main promise chain, and `has_in_flight_tx` is set to `true`.
2. Ensure the underlying multi-hop promise (`storage_balance_of` → `storage_deposit` → `ft_transfer` → `rlp_execute_callback`) fails (e.g., NEP-141 token call reverts), so `rlp_execute_callback` is invoked with `PromiseResult::Failed` and a non-`None` `caller_deposit`.
3. Craft/observe a scenario where the additional `env::promise_batch_create`/`env::promise_batch_action_transfer` refund calls inside `rlp_execute_callback`, combined with the fixed `RLP_EXECUTE_CALLBACK_GAS = 5 Tgas` budget, exhaust the attached gas, causing the callback itself to panic with `GasExceeded`.
4. Because the callback panicked, the entire receipt fails and its state changes — including `self.has_in_flight_tx = false` — are rolled back per `runtime/runtime/src/lib.rs` receipt-commit logic, leaving `has_in_flight_tx = true` persisted.
5. Any subsequent call to `rlp_execute` on this account now unconditionally returns `"Error: transaction already in progress, please try again later."` forever, with no way to clear the flag.

I could not execute/verify step 3 empirically against actual gas metering (would require running the contract under `near-vm-runner` with crafted inputs), so the exact gas amounts needed to trigger this are unconfirmed, but the structural vulnerability (state reset happening before further gas-consuming, panic-capable operations, all-or-nothing rollback semantics) is directly supported by the cited code.

### Citations

**File:** runtime/runtime/src/lib.rs (L946-955)
```rust
        match &result.result {
            Ok(_) => {
                state_update.commit(StateChangeCause::ReceiptProcessing {
                    receipt_hash: receipt.get_hash(),
                });
            }
            Err(_) => {
                state_update.rollback();
            }
        };
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L37-37)
```rust
const RLP_EXECUTE_CALLBACK_GAS: Gas = Gas::from_tgas(5);
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

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L96-105)
```rust
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

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L139-141)
```rust
    ) -> PromiseOrValue<ExecuteResponse> {
        self.has_in_flight_tx = false;
        let maybe_account_id: Option<AccountId> = match env::promise_result(0) {
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L201-203)
```rust
    ) -> PromiseOrValue<ExecuteResponse> {
        self.has_in_flight_tx = false;
        let maybe_storage_balance: Option<StorageBalance> = match env::promise_result(0) {
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L279-281)
```rust
    ) -> ExecuteResponse {
        self.has_in_flight_tx = false;
        let n = env::promise_results_count();
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L296-305)
```rust
        match env::promise_result(0) {
            PromiseResult::Failed => {
                // The cross-contract call failed, refund the caller if needed
                if let Some(CallerDeposit { account_id, yocto_near }) = caller_deposit {
                    let refund_promise = env::promise_batch_create(&account_id);
                    env::promise_batch_action_transfer(
                        refund_promise,
                        NearToken::from_yoctonear(yocto_near.into()),
                    );
                }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L319-322)
```rust
    #[private]
    pub fn ban_relayer(&mut self) -> ExecuteResponse {
        self.has_in_flight_tx = false;
        ExecuteResponse {
```
