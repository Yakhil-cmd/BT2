### Title
Wallet Contract `address_check_callback` Fails to Increment Nonce on Registrar Call Failure, Enabling Replay of User-Signed Ethereum Transactions - (File: runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs)

### Summary
When the address registrar cross-contract call returns `PromiseResult::Failed` inside `WalletContract::address_check_callback`, the wallet contract's `self.nonce` is never incremented and `has_in_flight_tx` is reset to `false`. This leaves the contract in a state where the same user-signed Ethereum transaction (carrying the same nonce) can be replayed by any unprivileged account, potentially spending the user's NEAR tokens without their current consent.

### Finding Description
`WalletContract` in `lib.rs` implements Ethereum-style meta transactions for ETH-implicit accounts. The `rlp_execute` entry point accepts a user-signed RLP-encoded Ethereum transaction and dispatches it as a NEAR action.

For `EOABaseTokenTransfer` transactions targeting another eth-implicit account, the nonce increment is intentionally deferred out of `inner_rlp_execute`. The conditional at lines 358–365 of `lib.rs` skips the `*nonce = nonce.saturating_add(1)` increment specifically for the `EOABaseTokenTransfer { address_check: Some(_) }` path, because the contract must first query the address registrar to determine whether the target address maps to a named NEAR account: [1](#0-0) 

The deferred increment is supposed to happen inside `address_check_callback` at line 178, but only in the `maybe_account_id.is_none()` branch (address not registered → transaction is valid): [2](#0-1) 

However, when `env::promise_result(0)` returns `PromiseResult::Failed` (registrar contract unavailable, panics, or runs out of gas), the function sets `has_in_flight_tx = false` at line 140 and immediately returns early at lines 142–148 **without ever incrementing `self.nonce`**: [3](#0-2) 

After this early return, the contract state is:
- `self.nonce` = N (unchanged)
- `self.has_in_flight_tx` = `false`

Because `has_in_flight_tx` is `false`, the guard at the top of `rlp_execute` (lines 97–104) does not block a subsequent call. Because `self.nonce` is still N, the nonce check inside `validate_tx_relayer_data` (`nonce != expected_nonce` at line 357 of `internal.rs`) passes for the same signed Ethereum transaction: [4](#0-3) 

The signed transaction bytes were submitted on-chain in the original `rlp_execute` call and are therefore visible to any observer. Any account can call `rlp_execute` with those same bytes to replay the transaction.

This contrasts with user errors in `inner_rlp_execute`, which do increment the nonce to prevent replay: [5](#0-4) 

The `get_nonce` docstring explicitly states the Ethereum protocol requirement that the nonce must be incremented even for failed transactions: [6](#0-5) 

The `PromiseResult::Failed` path violates this invariant.

### Impact Explanation
The exact corrupted value is `self.nonce`, which remains at N instead of advancing to N+1. Any account can replay the user's signed Ethereum transaction after a registrar failure. If the user's NEAR balance increases between the failed attempt and the replay (e.g., they receive a transfer), the replayed transaction will succeed, spending the user's NEAR tokens without their current consent. This is a direct, unauthorized fund loss from the user's ETH-implicit account.

### Likelihood Explanation
The address registrar call can fail if: (1) the registrar contract is temporarily unavailable, (2) the registrar contract panics, or (3) the relayer attaches insufficient gas for the registrar call. The signed transaction bytes are visible on-chain (submitted in the original `rlp_execute` call), so any observer can extract and replay them. The `rlp_execute` function is public and `#[payable]`, so no special privilege is required to call it. The likelihood is moderate: it requires a specific failure condition (registrar unavailable), but this is reachable in production.

### Recommendation
Increment `self.nonce` in the `PromiseResult::Failed` branch of `address_check_callback`, before the early return:

```rust
PromiseResult::Failed => {
    self.nonce = self.nonce.saturating_add(1); // prevent replay
    return PromiseOrValue::Value(ExecuteResponse {
        success: false,
        success_value: None,
        error: Some("Call to Address Registrar contract failed".into()),
    });
}
```

This is consistent with how user errors are handled in `inner_rlp_execute` (line 391) and with the Ethereum protocol requirement documented in `get_nonce`.

### Proof of Concept
1. Alice signs an Ethereum transaction (nonce=5) to transfer 10 NEAR to Bob's eth-implicit account (`0xBob...`).
2. Relayer calls `rlp_execute(target="0xBob...", tx_bytes_b64=<Alice's signed tx>)`.
3. `inner_rlp_execute` validates the transaction (nonce=5 == expected_nonce=5 ✓), skips the nonce increment (EOABaseTokenTransfer with `address_check: Some(_)` path), and schedules a registrar lookup.
4. The registrar call fails (`PromiseResult::Failed`) — e.g., the registrar contract is temporarily unavailable.
5. `address_check_callback` sets `has_in_flight_tx = false` and returns early **without incrementing `self.nonce`**.
6. Alice's nonce remains at 5; `has_in_flight_tx` is `false`.
7. Alice receives 20 NEAR from a friend, increasing her balance.
8. Attacker (any account) calls `rlp_execute(target="0xBob...", tx_bytes_b64=<Alice's signed tx>)` with the same bytes.
9. `inner_rlp_execute` validates: nonce=5 == expected_nonce=5 ✓, signature valid ✓.
10. The registrar lookup succeeds this time (registrar is back online).
11. `address_check_callback` increments the nonce and executes the transfer.
12. Alice loses 10 NEAR unexpectedly, against her will.

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L59-68)
```rust
    /// Return the nonce value currently stored in the contract.
    /// Following the Ethereum protocol, only transactions with nonce equal
    /// to the current value will be accepted.
    /// Additionally, the Ethereum protocol requires the nonce of an account increment
    /// by 1 each time a transaction with the correct nonce and a valid signature
    /// is submitted (even if that transaction eventually fails). In this way, each
    /// nonce value can only be used once (hence the name "nonce") and thus transaction
    /// replay is prevented.
    pub fn get_nonce(&self) -> U64 {
        U64(self.nonce)
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

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L174-178)
```rust
        } else {
            // We must increment the nonce at this point to prevent replay of the transaction.
            // Recall that the nonce was not incremented in `inner_rlp_execute` in the case that
            // the registrar contract was called (i.e. in the case we end up inside this callback).
            self.nonce = self.nonce.saturating_add(1);
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L358-365)
```rust
            if let TransactionKind::EthEmulation(EthEmulationKind::EOABaseTokenTransfer {
                address_check: Some(_),
                ..
            }) = &transaction_kind
            {
            } else {
                *nonce = nonce.saturating_add(1);
            }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L389-392)
```rust
        Err(err @ Error::User(_)) => {
            // Increment nonce on all user errors to prevent replay.
            *nonce = nonce.saturating_add(1);
            return Err(err);
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
