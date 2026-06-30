### Title
Permanent ERC-20 Token Loss in `ExitToNear` Precompile When `ft_transfer` Fails Without Refund Callback — (File: engine-precompiles/src/native.rs)

---

### Summary

The `ExitToNear` precompile irreversibly burns ERC-20 tokens on the EVM side before the corresponding NEP-141 `ft_transfer` promise executes. When the `error_refund` compile-time feature is absent, no failure-handling callback is attached to the promise. A malicious recipient can unregister their NEP-141 storage deposit between the burn and the asynchronous transfer, causing `ft_transfer` to fail with no recovery path and permanently destroying the sender's tokens.

---

### Finding Description

`ExitToNear::run()` processes an ERC-20 exit in two sequential steps that are not atomic:

**Step 1 — Irreversible burn (EVM side, synchronous):**
The ERC-20 contract calls the precompile, which records the burn. This is committed to EVM state immediately.

**Step 2 — Asynchronous NEAR promise:**
A `ft_transfer` (or `ft_transfer_call`) promise is scheduled against the NEP-141 contract. This executes in a *separate receipt* in the next NEAR block.

The callback that would handle a failed transfer is gated behind the `error_refund` feature flag:

```rust
// engine-precompiles/src/native.rs  lines 449–455
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,
};
```

For a standard ERC-20 exit (non-wNEAR), `transfer_near` is also `None`, so `callback_args` equals the default value. The promise branch then omits the callback entirely:

```rust
// engine-precompiles/src/native.rs  lines 470–483
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no callback attached
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs {
        base: transfer_promise,
        callback: PromiseCreateArgs {
            method: "exit_to_near_precompile_callback".to_string(),
            ...
        },
    })
};
```

NEP-141's `ft_transfer` panics if the recipient has no storage deposit. A recipient can call `storage_unregister` on the NEP-141 contract at any time. Because the NEAR promise executes one block after the EVM burn, there is a window in which the recipient can invalidate the destination. When `ft_transfer` panics, the promise fails silently — no refund is issued, and the burned tokens are gone.

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

ERC-20 tokens are destroyed on the EVM side (supply reduced, balance zeroed) but never credited on the NEAR side. The tokens cease to exist in any recoverable form. Any protocol or user that relies on `ExitToNear` for withdrawals can have their funds permanently destroyed by a malicious recipient.

---

### Likelihood Explanation

**Medium.**

- NEAR receipts execute one block (~1 second) after the originating transaction. This window is narrow but deterministic and observable on-chain.
- A malicious recipient watching the mempool (or coordinating with a block producer) can call `storage_unregister` in the same block as the `ExitToNear` transaction, ensuring the `ft_transfer` receipt finds no registered storage.
- In a DeFi protocol context (e.g., a lending or yield protocol on Aurora that sends ERC-20 tokens to users on exit), a malicious user can unregister their storage, trigger the protocol's exit path, and cause the protocol to permanently lose the tokens it attempted to send — without the attacker needing to sacrifice anything of value (they simply forgo receiving the tokens they were owed).
- No admin keys, governance capture, or privileged access is required. Any unprivileged EVM user or NEAR account holder can execute this.

---

### Recommendation

Unconditionally attach the `exit_to_near_precompile_callback` for all ERC-20 exits, regardless of whether the `error_refund` feature is compiled in. The callback should inspect the promise result and, on failure, re-mint the burned ERC-20 tokens to the original sender's EVM address. The `error_refund` feature flag should be removed or made always-on for production builds so that the refund path is never absent.

---

### Proof of Concept

1. **Setup:** Recipient `alice.near` holds storage deposit on `token.near` (a NEP-141 contract mirrored as an ERC-20 on Aurora). Sender `bob` holds 1000 units of the corresponding ERC-20 on Aurora.
2. **Attack:** Alice calls `storage_unregister(force: false)` on `token.near`, withdrawing her storage deposit. She now has no registered account on `token.near`.
3. **Trigger:** Bob (or a protocol acting on Bob's behalf) calls `ExitToNear` specifying `alice.near` as the recipient and 1000 tokens as the amount.
4. **Burn:** The ERC-20 precompile burns 1000 tokens from Bob's EVM balance. This is committed immediately. No callback is scheduled (because `error_refund` is absent and this is not a wNEAR exit).
5. **Failure:** In the next NEAR block, the `ft_transfer` receipt executes on `token.near`. Because Alice has no storage deposit, the call panics and the receipt fails.
6. **Result:** Bob's 1000 ERC-20 tokens are permanently destroyed. Alice receives nothing. No refund is issued. The total ERC-20 supply is reduced by 1000 with no corresponding NEP-141 credit.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** engine-precompiles/src/native.rs (L449-455)
```rust
        let callback_args = ExitToNearPrecompileCallbackArgs {
            #[cfg(feature = "error_refund")]
            refund: refund_call_args(&exit_to_near_params, &exit_event),
            #[cfg(not(feature = "error_refund"))]
            refund: None,
            transfer_near: transfer_near_args,
        };
```

**File:** engine-precompiles/src/native.rs (L470-483)
```rust
        let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
            PromiseArgs::Create(transfer_promise)
        } else {
            PromiseArgs::Callback(PromiseWithCallbackArgs {
                base: transfer_promise,
                callback: PromiseCreateArgs {
                    target_account_id: self.current_account_id.clone(),
                    method: "exit_to_near_precompile_callback".to_string(),
                    args: borsh::to_vec(&callback_args).unwrap(),
                    attached_balance: Yocto::new(0),
                    attached_gas: costs::EXIT_TO_NEAR_CALLBACK_GAS,
                },
            })
        };
```

**File:** engine-precompiles/src/native.rs (L558-647)
```rust
fn exit_erc20_token_to_near<I: IO>(
    context: &Context,
    exit_params: &Erc20TokenParams,
    io: &I,
) -> Result<
    (
        AccountId,
        String,
        events::ExitToNear,
        String,
        Option<TransferNearArgs>,
    ),
    ExitError,
> {
    // In case of withdrawing ERC-20 tokens, the `apparent_value` should be zero. In opposite way
    // the funds will be locked in the address of the precompile without any possibility
    // to withdraw them in the future. So, in case if the `apparent_value` is not zero, the error
    // will be returned to prevent that.
    if context.apparent_value != U256::zero() {
        return Err(ExitError::Other(Cow::from(
            "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
        )));
    }

    let erc20_address = context.caller; // because ERC-20 contract calls the precompile.
    let nep141_account_id = get_nep141_from_erc20(erc20_address.as_bytes(), io)?;

    let (nep141_account_id, args, method, transfer_near_args, event) = match exit_params.message {
        // wNEAR address should be set via the `factory_set_wnear_address` transaction first.
        Some(Message::UnwrapWnear) if erc20_address == get_wnear_address(io).raw() =>
        // The flow is following here:
        // 1. We call `near_withdraw` on wNEAR account id on `aurora` behalf.
        // In such way we unwrap wNEAR to NEAR.
        // 2. After that, we call callback `exit_to_near_precompile_callback` on the `aurora`
        // in which make transfer of unwrapped NEAR to the `target_account_id`.
        {
            (
                nep141_account_id,
                format!(r#"{{"amount":"{}"}}"#, exit_params.amount.as_u128()),
                "near_withdraw",
                Some(TransferNearArgs {
                    target_account_id: exit_params.receiver_account_id.clone(),
                    amount: exit_params.amount.as_u128(),
                }),
                events::ExitToNear::Legacy(ExitToNearLegacy {
                    sender: Address::new(erc20_address),
                    erc20_address: Address::new(erc20_address),
                    dest: exit_params.receiver_account_id.to_string(),
                    amount: exit_params.amount,
                }),
            )
        }
        // In this flow, we're just forwarding the `msg` to the `ft_transfer_call` transaction.
        Some(Message::Omni(msg)) => (
            nep141_account_id,
            ft_transfer_call_args(&exit_params.receiver_account_id, exit_params.amount, msg)?,
            "ft_transfer_call",
            None,
            events::ExitToNear::Omni(ExitToNearOmni {
                sender: Address::new(erc20_address),
                erc20_address: Address::new(erc20_address),
                dest: exit_params.receiver_account_id.to_string(),
                amount: exit_params.amount,
                msg: msg.to_string(),
            }),
        ),
        // The legacy flow. Just withdraw the tokens to the NEAR account id.
        // P.S. We use underscore here instead of `None` to handle the case when a user
        // could add the `unwrap` suffix for non wNEAR ERC-20 token by mistake.
        _ => {
            // There is no way to inject json, given the encoding of both arguments
            // as decimal and valid account id respectively.
            (
                nep141_account_id,
                format!(
                    r#"{{"receiver_id":"{}","amount":"{}"}}"#,
                    exit_params.receiver_account_id,
                    exit_params.amount.as_u128()
                ),
                "ft_transfer",
                None,
                events::ExitToNear::Legacy(ExitToNearLegacy {
                    sender: Address::new(erc20_address),
                    erc20_address: Address::new(erc20_address),
                    dest: exit_params.receiver_account_id.to_string(),
                    amount: exit_params.amount,
                }),
            )
        }
    };
```

**File:** engine/src/contract_methods/connector.rs (L196-200)
```rust
pub fn exit_to_near_precompile_callback<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<Option<SubmitResult>, ContractError> {
```
