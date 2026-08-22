## Analog Finding

### Title
Stale signed Ethereum-emulation transaction remains permanently replayable after a relayer-side failure, allowing later unauthorized execution - (File: `runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs`)

### Summary
The `MultiSigWalletBase.sol` report describes a class of bug where a transaction that reverts is not permanently invalidated: some later condition lets the *same* transaction execute successfully, even though the caller expected the revert to be final. The analogous pattern exists in the NEAR Wallet Contract (`near-wallet-contract`), which emulates Ethereum EOA semantics on NEAR. When the `address_check` step of an emulated base-token transfer fails, the contract's `nonce` (its analog of the Solidity "permission to execute") is never incremented, leaving the exact same signed RLP transaction indefinitely valid for later execution by anyone holding the bytes.

### Finding Description
`rlp_execute` is the sole entry point for executing a user-signed Ethereum-style transaction against the wallet contract's underlying NEAR account [1](#0-0) . For most transaction kinds, `inner_rlp_execute` increments `self.nonce` immediately once parsing succeeds, which prevents replay regardless of whether the follow-up cross-contract call later succeeds or fails [2](#0-1) .

However, for `EOABaseTokenTransfer { address_check: Some(_), .. }`, the nonce increment is explicitly deferred to `address_check_callback`, with the code comment stating this is because "the error is caused by a faulty relayer, not the user" [3](#0-2) . In `address_check_callback`, if the cross-contract call to the address registrar fails (`PromiseResult::Failed`), the function returns a failure response and resets `has_in_flight_tx = false` — but it never touches `self.nonce` [4](#0-3) .

Because the whole receipt fails and NEAR's `TrieUpdate` rolls back all state changes on failure [5](#0-4) , `nonce` and `has_in_flight_tx` are restored exactly as they were before this attempt. The net effect: the previously-submitted signed Ethereum transaction bytes are still valid indefinitely — `validate_tx_relayer_data` will accept them again as long as `tx.nonce == expected_nonce` [6](#0-5) . Unlike a real Ethereum mempool (where gas-price competition and node-level nonce tracking naturally displace stale transactions), there is no expiry, deadline, or cancellation mechanism in this contract: the same signed blob (visible in a prior NEAR transaction's function-call args, hence public) can be re-submitted by *any* relayer at any future point in time and will be treated as a fresh, currently-valid instruction.

### Impact Explanation
This mirrors the original report's core danger: a transaction that "reverted" is not actually dead — "the permission to execute remains with this transaction." Here, the permission is the wallet's nonce. A user who intends to abandon or supersede a base-token transfer (because a registrar lookup happened to fail) has no way to invalidate it: it will retain the current expected nonce and can be executed later, at a time chosen by whoever holds the bytes, transferring the user's NEAR without their present-moment consent (unauthorized balance change). It also enables a relayer to intentionally trigger the address-check-failure branch and then hold the transaction to execute at a more advantageous moment (e.g., to collect the attached relayer fee under different market/gas conditions), since the fee refund logic is tied to submission of this stale transaction [7](#0-6) .

### Likelihood Explanation
This requires the Wallet Contract to be deployed and used with an `address_check`-eligible base-token transfer (target not yet registered in the address registrar) and a relayer/registrar-side transient failure — a normal, expected operational condition, not an attacker-controlled edge case. Any party with the previously-broadcast signed bytes (which are stored as plaintext function-call arguments in a past NEAR transaction, hence publicly retrievable from the chain) can act as the "relayer" for a later resubmission.

### Recommendation
Do not treat relayer-side failures during the `address_check` phase as fully reversible without cost: either increment the nonce (invalidating the specific signed instruction) even on registrar-lookup failure, or introduce an explicit expiry/deadline field validated in `validate_tx_relayer_data` so a stale signed transaction cannot be replayed indefinitely after a failed attempt.

### Proof of Concept
Conceptual scenario, not verified end-to-end due to index limitations on exact wallet-contract test harness state:
1. User signs an Ethereum-style base-token transfer transaction (`nonce = N`) targeting an unregistered address, submitted via a relayer to `rlp_execute`.
2. `inner_rlp_execute` takes the `address_check: Some(address)` branch and does *not* increment `nonce` (still `N`) [8](#0-7) .
3. The registrar lookup call fails (e.g., registrar contract temporarily out of gas/unavailable), so `address_check_callback` returns failure, and `self.nonce` remains `N` after the receipt rollback [4](#0-3) .
4. User, believing the transfer failed permanently, moves on (e.g., changes their mind about sending funds, or the target account later becomes attacker-controlled/registered).
5. At an arbitrary later time, anyone holding the originally-signed RLP bytes resubmits the same transaction via `rlp_execute`; `validate_tx_relayer_data` still finds `tx.nonce (N) == expected_nonce (N)` and accepts it, executing the transfer as "success" even though it had previously failed/reverted.

Given the scope of this investigation and index limits, I was not able to fully trace whether downstream production integrations (e.g., relayer services) add their own client-side nonce/expiry safeguards outside this contract; the vulnerability described is specific to the on-chain contract logic itself.

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L89-115)
```rust
    pub fn rlp_execute(
        &mut self,
        target: AccountId,
        tx_bytes_b64: String,
    ) -> PromiseOrValue<ExecuteResponse> {
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

```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L140-148)
```rust
        self.has_in_flight_tx = false;
        let maybe_account_id: Option<AccountId> = match env::promise_result(0) {
            PromiseResult::Failed => {
                return PromiseOrValue::Value(ExecuteResponse {
                    success: false,
                    success_value: None,
                    error: Some("Call to Address Registrar contract failed".into()),
                });
            }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L161-178)
```rust
        let promise = if maybe_account_id.is_some() {
            // We intentionally do not increment the nonce in this case because the
            // error is caused by a faulty relayer, not the user. An honest relayer
            // may still be able to successfully send the user's intended transaction.
            if env::signer_account_id() == current_account_id {
                create_ban_relayer_promise(current_account_id)
            } else {
                return PromiseOrValue::Value(ExecuteResponse {
                    success: false,
                    success_value: None,
                    error: Some("Invalid target: target is address corresponding to existing named account_id".into()),
                });
            }
        } else {
            // We must increment the nonce at this point to prevent replay of the transaction.
            // Recall that the nonce was not incremented in `inner_rlp_execute` in the case that
            // the registrar contract was called (i.e. in the case we end up inside this callback).
            self.nonce = self.nonce.saturating_add(1);
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L347-365)
```rust
    let parsing_result = internal::parse_rlp_tx_to_action(&tx_bytes_b64, &target, &context, *nonce);
    let (action, transaction_kind) = match parsing_result {
        Ok((action, transaction_kind)) => {
            // Increment nonce for all cases where the registrar contract is not needed
            // to prevent replay of those transactions. For transactions that go through
            // the registrar we still do not know if the transaction has a relayer error
            // or not, therefore we must delay incrementing the nonce.
            //
            // Note: relayers with access keys cannot use this delay to needlessly spend
            // the users tokens because only one transaction is allowed to be in-flight
            // at a time.
            if let TransactionKind::EthEmulation(EthEmulationKind::EOABaseTokenTransfer {
                address_check: Some(_),
                ..
            }) = &transaction_kind
            {
            } else {
                *nonce = nonce.saturating_add(1);
            }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L366-385)
```rust

            // If the action is an emulated base token or ERC-20 transfer with a non-zero fee then
            // create a promise to send the refund to the relayer. This allows any relayer
            // to safely serve base token transfers from any wallet without additional
            // on-boarding because the relayer will receive some compensation for sending
            // the transaction. Users should always verify the fee before signing a base token
            // transfer. Relayers should also verify the fee before sending to make sure the
            // user's signed transaction will refund enough to cover the relayer's gas costs.
            if let TransactionKind::EthEmulation(EthEmulationKind::EOABaseTokenTransfer {
                fee,
                ..
            })
            | TransactionKind::EthEmulation(EthEmulationKind::ERC20Transfer { fee, .. }) =
                &transaction_kind
            {
                if !fee.is_zero() && context.predecessor_account_id != context.current_account_id {
                    let refund_promise = env::promise_batch_create(&context.predecessor_account_id);
                    env::promise_batch_action_transfer(refund_promise, *fee);
                }
            }
```

**File:** runtime/runtime/AGENTS.md (L60-64)
```markdown
Each account can have multiple access keys, which are used to validate transactions submitted for this account. NEAR supports named accounts which don't have the public key in their name (e.g. `alice.near`). When a transaction is submitted, the verification code fetches the account's access key and verifies the transaction's signature against this key.

Receipts are not signed, so they're not validated using access keys. Receipts can be trusted because their hash has been signed by 2/3 of the chunk validator stake.

To modify the shard's state, the runtime uses `TrieUpdate`. This struct applies changes on top of the chunk's pre-state. It allows to rollback or commit recent changes. When a receipt fails, its state changes are rolled back using `TrieUpdate`.
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs (L352-359)
```rust
    let nonce = if tx.nonce <= U64_MAX {
        tx.nonce.low_u64()
    } else {
        return Err(Error::Relayer(RelayerError::InvalidNonce));
    };
    if nonce != expected_nonce {
        return Err(Error::Relayer(RelayerError::InvalidNonce));
    }
```
