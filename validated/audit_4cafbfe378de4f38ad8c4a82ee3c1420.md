Based on the analysis, there's a concrete analog in the `near-wallet-contract` implementation, which is reachable via an unprivileged external caller (relayer) sending a NEAR transaction with an attached deposit.

### Title
Attached deposit from an external caller is permanently lost when `address_check_callback` rejects a target address without refunding `CallerDeposit` - (File: `runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs`)

### Summary
The `WalletContract::rlp_execute` entry point captures the caller's `attached_deposit` into a `CallerDeposit` struct whenever the predecessor (caller) differs from the wallet's own account, with the explicit purpose of refunding that deposit if the emulated Ethereum transaction ultimately fails to execute. This refund mechanism is implemented in `rlp_execute_callback`, but one specific failure branch inside `address_check_callback` returns an error response directly as a value instead of scheduling a promise, silently dropping the `caller_deposit` parameter and never refunding it.

### Finding Description
`CallerDeposit::new` records the predecessor's attached deposit whenever the predecessor is not the wallet contract itself: [1](#0-0) 

This deposit is threaded through `inner_rlp_execute` into `address_check_callback` for the `EOABaseTokenTransfer` path that requires verifying the target address against the address registrar: [2](#0-1) 

Inside `address_check_callback`, when the registrar lookup shows the target address is already claimed by a named account, and the transaction was **not** submitted through the wallet's own access key (`signer_account_id != current_account_id`, i.e. an honest external relayer/caller path), the function returns an error `ExecuteResponse` directly as a `Value` — completely discarding the `caller_deposit` parameter that was passed in: [3](#0-2) 

By contrast, the designed refund path in `rlp_execute_callback` explicitly creates a `promise_batch_action_transfer` back to the caller whenever the underlying promise fails: [4](#0-3) 

This is structurally the same bug class as the wfCash report: a fallback/error branch that the developer assumed would either "never happen" or didn't need the refund treatment applied elsewhere, resulting in caller funds being silently absorbed by the contract instead of following the intended refund path. In NEAR, an attached deposit that is not explicitly transferred back becomes part of the receiving contract's own account balance permanently — there is no automatic protocol-level return of unspent deposit to the caller once it is credited to the receiver.

### Impact Explanation
Any external caller/relayer (unprivileged account, not holding an access key on the wallet contract) that calls `rlp_execute` with a non-zero attached deposit and a target address that happens to already correspond to a registered named account will have that entire deposit stuck in the wallet contract with no recovery path — a direct, permanent loss of the caller's NEAR tokens. Since relayer flows are exactly the intended real-world use case for this contract (per the design comments about relayers being compensated via `fee`), this is a realistic, unprivileged-account-reachable loss of funds.

### Likelihood Explanation
This requires: (1) an external account other than the wallet owner submitting the transaction (not using the wallet's own access key — the common relayer case), (2) attaching a non-zero deposit, and (3) the transaction's target Ethereum-style address resolving to an address that is already registered under a named NEAR account in the address registrar. Condition (3) is a legitimate, non-adversarial scenario (e.g., stale client-side address resolution, or a target address later getting registered), making this reachable without any privileged or malicious-node behavior — a normal user/relayer error path.

### Recommendation
In the `address_check_callback` branch that returns `PromiseOrValue::Value(...)` for the "target is an existing named account" error case, schedule a refund promise for `caller_deposit` (mirroring the logic already present in `rlp_execute_callback`'s `PromiseResult::Failed` branch) before returning the error response, instead of discarding the deposit silently.

### Proof of Concept
1. Deploy a `WalletContract` for an eth-implicit account.
2. Have an external relayer account (distinct from the wallet account) call `rlp_execute` with a non-zero attached deposit, providing an RLP-encoded Ethereum transaction whose `target` decodes to `EthEmulationKind::EOABaseTokenTransfer { address_check: Some(address), .. }`.
3. Ensure the target `address` is already registered to a named account in the address registrar contract (simulating `maybe_account_id.is_some()` in `address_check_callback`).
4. Observe: `address_check_callback` returns `ExecuteResponse{success:false,...}` directly; no refund promise is created for the relayer's attached deposit, and the wallet contract's balance permanently retains the deposit (contrast with `test_caller_refunds` in `runtime/near-wallet-contract/implementation/wallet-contract/src/tests/sanity.rs`, which verifies the refund happens for the `Failed` promise path but does not cover this specific `address_check_callback` early-return branch).

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/types.rs (L180-191)
```rust
impl CallerDeposit {
    pub fn new(context: &ExecutionContext) -> Option<Self> {
        // Only track for external (non-self) callers
        if context.current_account_id == context.predecessor_account_id {
            return None;
        }

        NonZeroU128::new(context.attached_deposit.as_yoctonear()).map(|yocto_near| Self {
            account_id: context.predecessor_account_id.clone(),
            yocto_near,
        })
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L160-192)
```rust
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

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L296-317)
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

                ExecuteResponse {
                    success: false,
                    success_value: None,
                    error: Some("Failed Near promise".into()),
                }
            }
            PromiseResult::Successful(value) => {
                ExecuteResponse { success: true, success_value: Some(value), error: None }
            }
        }
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
