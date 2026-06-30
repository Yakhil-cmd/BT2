### Title
ERC-20 Tokens Permanently Burned When `ft_transfer_call` Returns Partial Amount in `ExitToNear` Omni Path — (`engine-precompiles/src/native.rs`)

---

### Summary

When a user calls `withdrawToNear` with an Omni-style message on `EvmErc20.sol`, ERC-20 tokens are burned atomically in the EVM before the NEAR-side `ft_transfer_call` executes. If the NEP-141 receiver's `ft_on_transfer` returns a non-zero `unused_amount` (a partial transfer, which is explicitly allowed by the NEP-141 standard), those tokens are returned to Aurora's NEP-141 balance by the NEP-141 contract's `ft_resolve_transfer`. However, the corresponding ERC-20 tokens are already permanently burned with no refund path, causing a direct loss of user funds.

---

### Finding Description

**Step 1 — ERC-20 tokens are burned unconditionally.**

`EvmErc20.withdrawToNear` burns the caller's tokens before the NEAR promise is even scheduled:

```solidity
// etc/eth-contracts/contracts/EvmErc20.sol:53-62
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // <-- irreversible burn
    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    uint input_size = 1 + 32 + recipient.length;
    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
    }
}
``` [1](#0-0) 

**Step 2 — The Omni path schedules `ft_transfer_call` with `transfer_near_args = None`.**

In `exit_erc20_token_to_near`, the Omni branch sets `transfer_near_args` to `None`:

```rust
// engine-precompiles/src/native.rs:611-623
Some(Message::Omni(msg)) => (
    nep141_account_id,
    ft_transfer_call_args(&exit_params.receiver_account_id, exit_params.amount, msg)?,
    "ft_transfer_call",
    None,   // <-- transfer_near_args is None
    ...
),
``` [2](#0-1) 

**Step 3 — The callback only handles complete failure, not partial success.**

`exit_to_near_precompile_callback` branches on `PromiseResult::Successful` vs. failure. When `ft_transfer_call` succeeds (even partially), the callback takes the `Successful` branch and does nothing — no check of the actual amount transferred, no re-mint of the difference:

```rust
// engine/src/contract_methods/connector.rs:214-230
let maybe_result = if let Some(PromiseResult::Successful(_)) = handler.promise_result(0) {
    if let Some(args) = args.transfer_near {
        // Only executed for the wNEAR unwrap path
        ...
    }
    None   // <-- Omni path: nothing happens even if partial transfer occurred
} else if let Some(args) = args.refund {
    // Only executed on complete failure
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
    ...
}
``` [3](#0-2) 

**Step 4 — NEP-141 standard allows partial transfers.**

`ft_transfer_call` in NEP-141 calls `ft_on_transfer` on the receiver, which may return `unused_amount > 0`. The NEP-141 contract's `ft_resolve_transfer` then returns those tokens to Aurora's NEP-141 balance. Aurora's balance is silently increased by `unused_amount`, but the ERC-20 tokens for that amount are already burned and no re-mint occurs.

**Net accounting mismatch:**
- User burned: `X` ERC-20 tokens
- Recipient received: `X - unused_amount` NEP-141 tokens
- Aurora's NEP-141 balance: increased by `unused_amount` (orphaned, no ERC-20 backing)
- User's loss: `unused_amount` tokens, permanently

---

### Impact Explanation

This is a **permanent freezing / direct theft of user funds**. The user burns `X` ERC-20 tokens expecting `X` NEP-141 tokens to reach the recipient. If the recipient's `ft_on_transfer` returns any amount, the user loses that amount with no recourse. The transaction does not revert, no error is surfaced to the EVM caller, and no re-mint is triggered. The orphaned NEP-141 tokens remain in Aurora's balance indefinitely.

This is the direct analog of the EIP-4626 `withdraw` bug: a function promises to transfer exactly `assets` but silently delivers less, without reverting.

---

### Likelihood Explanation

The NEP-141 `ft_transfer_call` / `ft_on_transfer` partial-return pattern is a standard, documented feature used by DeFi protocols on NEAR (e.g., AMMs that reject excess input, lending protocols with capacity limits). Any user who routes an Omni exit through such a protocol will silently lose the returned portion. The entry path is fully unprivileged: any EVM user holding ERC-20 tokens can call `withdrawToNear` with an Omni message.

---

### Recommendation

In `exit_to_near_precompile_callback`, when the promise result is `Successful`, read the actual amount transferred from the `ft_transfer_call` result (the NEP-141 contract returns the net transferred amount). Compute `refund_amount = burned_amount - actual_transferred`. If `refund_amount > 0`, re-mint that amount of ERC-20 tokens to the original sender, mirroring the logic already present in `refund_on_error`.

Alternatively, enforce that `ft_transfer_call` must transfer the full amount or revert, by checking the promise result value in the callback and panicking if the returned `unused_amount` is non-zero.

---

### Proof of Concept

1. Alice holds 1000 `EvmErc20` tokens on Aurora (backed by 1000 NEP-141 tokens in Aurora's balance).
2. Alice calls `withdrawToNear(omni_receiver_account, 1000)` with an Omni message targeting a NEAR AMM.
3. `_burn(Alice, 1000)` executes — Alice's ERC-20 balance is now 0.
4. The precompile schedules `ft_transfer_call(receiver=amm, amount=1000, msg=omni_msg)` on the NEP-141 contract.
5. The AMM's `ft_on_transfer` accepts only 700 tokens (e.g., slippage limit) and returns `unused_amount = 300`.
6. NEP-141's `ft_resolve_transfer` returns 300 tokens to Aurora's NEP-141 balance.
7. `exit_to_near_precompile_callback` fires with `PromiseResult::Successful(_)` — no re-mint, no refund.
8. Alice has lost 300 ERC-20 tokens permanently. The AMM received 700 NEP-141 tokens. Aurora holds 300 orphaned NEP-141 tokens.

### Citations

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-63)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** engine-precompiles/src/native.rs (L611-623)
```rust
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
```

**File:** engine/src/contract_methods/connector.rs (L214-230)
```rust
        let maybe_result = if let Some(PromiseResult::Successful(_)) = handler.promise_result(0) {
            if let Some(args) = args.transfer_near {
                let action = PromiseAction::Transfer {
                    amount: Yocto::new(args.amount),
                };
                let promise = PromiseBatchAction {
                    target_account_id: args.target_account_id,
                    actions: vec![action],
                };

                // Safety: this call is safe because it comes from the exit to near precompile, not users.
                // The call is to transfer the unwrapped wNEAR tokens.
                let promise_id = handler.promise_create_batch(&promise);
                handler.promise_return(promise_id);
            }

            None
```
