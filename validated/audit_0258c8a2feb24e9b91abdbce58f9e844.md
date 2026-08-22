Now I understand the full mechanism: the address-check flow exists precisely to detect a "faulty relayer" that routes what should be a base-token-transfer-to-a-registered-account through the wrong path. This makes the hardcoded registrar address analog concretely exploitable.

### Title
Hardcoded `ADDRESS_REGISTRAR_ACCOUNT_ID` ("address-map.near") in the Wallet Contract lets an attacker defeat relayer-fraud detection and misroute Near/ERC-20 emulated transfers to a squatted account - ([File: runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs])

### Summary
The Wallet Contract, deployed as code on every ETH-implicit account (per NEP-518), hardcodes the account ID of its trusted Address Registrar contract at compile time via `include_str!("ADDRESS_REGISTRAR_ACCOUNT_ID")`, whose contents are the literal string `address-map.near`. [1](#0-0) [2](#0-1) 
This value is never validated against genesis config, `chain_id`, or any admin-controlled setting; it is baked into the wasm binary shipped for every deployment of the contract.

### Finding Description
`inner_rlp_execute` parses the account ID directly from the compiled-in string and only checks that it parses as a syntactically valid `AccountId` — it does not verify that the account exists, is owned by a trusted party, or corresponds to the real, canonical registrar deployed by the protocol on that particular network: [3](#0-2) 

This registrar lookup is the sole security check used to detect a faulty/malicious relayer routing a base-token or emulated ERC-20 transfer to another eth-implicit "address" target instead of the real registered named account that the address corresponds to. The check exists specifically because `validate_tx_relayer_data`/`parse_rlp_tx_to_action` cannot otherwise tell whether an address the user intends to pay actually maps to a named account: [4](#0-3) 
If the registrar says the address IS registered to a named account, the contract treats the relayer as faulty and bans it (protecting the user from misrouted funds); if the registrar says the address is unregistered, the contract proceeds and (irreversibly) sends the transfer to the eth-implicit-looking target: [5](#0-4) 

Because `address-map.near` is just an ordinary, permissionless NEAR account name, anyone can create/own an account with that exact name on any network where the canonical protocol registrar has not already claimed it first (e.g., testnet, a fresh localnet, or any other independently operated NEAR-protocol-compatible chain built from this codebase). An attacker who controls `address-map.near` on such a network can deploy a fake registrar contract whose `lookup` method always returns `None`, regardless of whether the target account was actually registered: [6](#0-5) 
Because the wallet contract blindly calls this hardcoded name and only checks the boolean-shaped answer, the anti-fraud check becomes a no-op: a malicious/lazy relayer can now freely misroute EOA base-token transfers or ERC-20 (NEP-141) transfers intended for a named account to the wrong eth-implicit account, and the wallet contract will believe it, incrementing the nonce and completing the transfer as if the relayer were honest.

This is directly analogous to the reported bug class: a security/routing-critical contract address is hardcoded rather than being derived from genesis/network configuration or set through an authenticated admin mechanism, so on any network besides the one the constant was intended for, the address does not point to the trusted contract, and value can be misdirected — the exact "hardcoded router causes fund routing to the wrong destination on non-standard networks" pattern from the report, here manifesting as unauthorized/misrouted balance changes instead of pure lockup.

### Impact Explanation
On any NEAR-protocol network where the operator/foundation has not pre-claimed `address-map.near` before the wallet-contract binary is used (testnet, custom/private chains, or even a delayed land-grab before the mainnet registrar exists), an attacker can:
1. Register `address-map.near` with a malicious contract that always returns `None` from `lookup`.
2. Operate as a relayer (or collude with one) that intentionally sets `target` to an eth-implicit "address" account instead of the correct named account for base-token or ERC-20 transfers.
3. Have the wallet contract's `address_check_callback` treat the transfer as legitimate (since the fake registrar reports "not registered"), causing the user's funds/tokens to be sent to the wrong account and the transaction to be finalized (nonce incremented), which is irreversible and prevents replay/retry by an honest relayer.

This results in unauthorized diversion of user balances (NEAR or NEP-141 tokens) with no on-chain signal that anything is wrong, since the contract logic considers this to be the "no address collision" happy path.

### Likelihood Explanation
Likelihood is moderate to high on any network other than a network where `address-map.near` has already been reserved by a trusted party before the wallet contract is used, since NEAR account names are first-come-first-served and require no special privilege to claim. On mainnet this is mitigated only if the protocol registers `address-map.near` before any eth-implicit account transacts; there is no code-level guarantee of this ordering, and the constant provides no fallback verification (e.g., checking a well-known code hash) if the account is later reused, migrated, or if the contract is deployed on any other chain derived from this codebase (private/enterprise chains, testnets, alternate NEAR-compatible networks) where this specific account name was never reserved.

### Recommendation
Do not rely on a bare hardcoded account-name string as the trust anchor for the registrar. At minimum:
- Verify the code hash of `address-map.near` (or whatever registrar account is configured) matches an expected, protocol-published hash before trusting its `lookup` response, or
- Make the registrar account ID a per-network/genesis-configured parameter validated at contract initialization rather than an `include_str!` constant baked into the wasm, and/or
- Require that `address-map.near` be part of genesis records (similar to `protocol_treasury_account`) so its ownership is guaranteed atomically at chain creation instead of being subject to a name-squatting race after genesis.

### Proof of Concept
Not independently executable from the indexed code alone (would require deploying a malicious `address-map.near` contract on a test/alternate network and driving `rlp_execute` with an `EOABaseTokenTransfer`/`ERC20Transfer` whose `target` is an eth-implicit "address" account that in fact corresponds to a real registered named account). The reachable path is fully supported by the code cited above: `rlp_execute` → `inner_rlp_execute` (registrar lookup at [7](#0-6)  ) → `address_check_callback` (trust decision at [8](#0-7)  ), with the registrar's `lookup` implementation confirmed to be a plain, unauthenticated account call as shown in `address-registrar/src/lib.rs`.

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L26-27)
```rust
const MICRO_NEAR: u128 = 10_u128.pow(18);
const ADDRESS_REGISTRAR_ACCOUNT_ID: &str = std::include_str!("ADDRESS_REGISTRAR_ACCOUNT_ID");
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L141-192)
```rust
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
        let current_account_id = env::current_account_id();
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
            let ext =
                WalletContract::ext(current_account_id).with_static_gas(RLP_EXECUTE_CALLBACK_GAS);
            match action_to_promise(target, action)
                .map(|p| p.then(ext.rlp_execute_callback(caller_deposit)))
            {
                Ok(p) => p,
                Err(e) => {
                    return PromiseOrValue::Value(e.into());
                }
            }
        };
        self.has_in_flight_tx = true;
        PromiseOrValue::Promise(promise)
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L412-431)
```rust
    let promise = match transaction_kind {
        TransactionKind::EthEmulation(EthEmulationKind::EOABaseTokenTransfer {
            address_check: Some(address),
            ..
        }) => {
            let callback_gas = ADDRESS_CHECK_CALLBACK_GAS.saturating_add(action.gas());
            let ext = WalletContract::ext(current_account_id).with_static_gas(callback_gas);
            let address_registrar = {
                let account_id = ADDRESS_REGISTRAR_ACCOUNT_ID
                    .trim()
                    .parse()
                    .unwrap_or_else(|_| env::panic_str("Invalid address registrar"));
                ext_registrar::ext(account_id).with_static_gas(REGISTRAR_LOOKUP_GAS)
            };
            let address = format!("0x{}", hex::encode(address));
            address_registrar.lookup(address).then(ext.address_check_callback(
                target,
                action,
                caller_deposit,
            ))
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/ADDRESS_REGISTRAR_ACCOUNT_ID (L1-1)
```text
address-map.near
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs (L66-122)
```rust
    // The way an honest relayer assigns `target` is as follows:
    // 1. If the Ethereum transaction payload represents a Near action then use the receiver_id,
    // 2. If the payload looks like a supported Ethereum emulation then use the address registrar:
    // 2.a. if the tx.to address is registered then use the associated account id,
    // 2.b. otherwise, tx.to == target
    // 3. Otherwise, tx.to == target
    // Given this algorithm, the only way to have `TargetKind::EthImplicit` is in the
    // following cases:
    // I)   The Ethereum transaction payload is not parseable as a known action,
    // II)  The payload is parsable as a Near action and the receiver_id is an eth-implicit account
    // III) The payload is parsable as a supported Ethereum emulation but the to address is
    //      not registered in the address registrar.
    // Therefore, to determine if the relayer is honest we must always parse the payload and
    // we only need to check the registrar if the payload is parseable as an Ethereum emulation.
    // Note: the `TargetKind` is determined in `validate_tx_relayer_data` above, and that function
    // also confirms that the `target` is compatible with the user's `tx.to`.

    let (action, transaction_kind) = match parse_tx_data(target, &tx, tx_fee, context) {
        Ok((action, ParsableTransactionKind::NearNativeAction)) => {
            (action, TransactionKind::NearNativeAction)
        }
        Ok((action, ParsableTransactionKind::SelfNearNativeAction)) => {
            if let TargetKind::EthImplicit(_) = target_kind {
                // The calldata was parseable as a Near native action where the target
                // should be the current account, but the target is some other wallet contract.
                // This is technically allowed under the Ethereum standard for base token transfers
                // (where any calldata can be used when sending tokens to another EOA), so we
                // assume such a transfer must have been the user's intent. No address check is
                // required in this case because no Near account other than the current account
                // can be the receiver of these actions.
                (
                    Action::Transfer { receiver_id: target.to_string(), yocto_near: 0 },
                    TransactionKind::EthEmulation(EthEmulationKind::EOABaseTokenTransfer {
                        address_check: None,
                        fee: tx_fee,
                    }),
                )
            } else {
                (action, TransactionKind::NearNativeAction)
            }
        }
        Ok((action, ParsableTransactionKind::EthEmulation(eth_emulation))) => {
            if let TargetKind::EthImplicit(address) = target_kind {
                // Even though the action was parsable, the target is another wallet contract,
                // so the action _must_ still be a base token transfer, but we need
                // to check if the target is not registered (otherwise the relayer is faulty).
                (
                    Action::Transfer { receiver_id: target.to_string(), yocto_near: 0 },
                    TransactionKind::EthEmulation(EthEmulationKind::EOABaseTokenTransfer {
                        address_check: Some(address),
                        fee: tx_fee,
                    }),
                )
            } else {
                (action, TransactionKind::EthEmulation(eth_emulation.into()))
            }
        }
```

**File:** runtime/near-wallet-contract/implementation/address-registrar/src/lib.rs (L94-102)
```rust
    pub fn lookup(&self, address: String) -> Option<AccountId> {
        let address = {
            let mut buf = [0u8; 20];
            hex::decode_to_slice(address.strip_prefix("0x").unwrap_or(&address), &mut buf)
                .unwrap_or_else(|_| env::panic_str("Invalid hex encoding"));
            buf
        };
        self.addresses.get(&address).cloned()
    }
```
