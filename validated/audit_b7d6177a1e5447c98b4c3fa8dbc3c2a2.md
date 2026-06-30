### Title
Rebasing/Fee-on-Transfer NEP-141 Tokens Cause ERC-20 Mirror Insolvency and Permanent Fund Freeze - (File: `engine/src/engine.rs`, `engine-precompiles/src/native.rs`, `etc/eth-contracts/contracts/EvmErc20.sol`)

---

### Summary

Aurora's NEP-141 → ERC-20 bridge mints ERC-20 tokens equal to the `amount` field in the `ft_on_transfer` callback, without any mechanism to account for a decrease in Aurora's actual NEP-141 custody balance. If the bridged NEP-141 token is a rebasing token (balance decreases autonomously) or a fee-on-transfer token (Aurora receives less than the stated amount), the ERC-20 total supply permanently exceeds Aurora's real NEP-141 balance. The last user(s) to call `withdrawToNear` will have their ERC-20 tokens burned but the downstream `ft_transfer` on the NEP-141 contract will fail, resulting in permanent loss of funds when the `error_refund` feature is not compiled in.

---

### Finding Description

**Bridge deposit path — `receive_erc20_tokens`:**

When a NEP-141 token is transferred to Aurora via `ft_transfer_call`, the NEP-141 contract invokes Aurora's `ft_on_transfer`. Aurora's handler calls `receive_erc20_tokens`, which mints exactly `args.amount` ERC-20 tokens for the recipient:

```rust
// engine/src/engine.rs
let amount = args.amount.as_u128();
// ...
setup_receive_erc20_tokens_input(&recipient, amount)  // mints `amount` ERC-20 tokens
```

The `args.amount` value is whatever the NEP-141 contract reports — it is never cross-checked against Aurora's actual post-transfer NEP-141 balance. For a **fee-on-transfer** NEP-141 token, Aurora receives `amount - fee` tokens but mints `amount` ERC-20 tokens. For a **rebasing** NEP-141 token, Aurora's custody balance can decrease at any time after minting, without any corresponding burn of ERC-20 tokens.

**Bridge withdrawal path — `withdrawToNear` / `ExitToNear` precompile:**

When a user exits, `EvmErc20.sol` burns the ERC-20 tokens first, then calls the `ExitToNear` precompile:

```solidity
// etc/eth-contracts/contracts/EvmErc20.sol
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ERC-20 burned here — irreversible
    // ... calls ExitToNear precompile
}
```

The precompile schedules an `ft_transfer` promise on the NEP-141 contract for the stated `amount`. If Aurora's actual NEP-141 balance is less than `amount` (due to rebasing or accumulated fee-on-transfer shortfall), the NEP-141 `ft_transfer` call fails.

**Refund path — conditional on `error_refund` feature:**

The `ExitToNear` precompile only populates the refund field in the callback args when compiled with `error_refund`:

```rust
// engine-precompiles/src/native.rs
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,
};
```

Without `error_refund`, when `ft_transfer` fails, `exit_to_near_precompile_callback` receives `refund: None` and takes no action — the burned ERC-20 tokens are permanently destroyed with no NEP-141 received.

**Permissionless entry:**

`deploy_erc20_token` has no owner/admin guard — any NEAR account can register any NEP-141 token as an ERC-20 mirror on Aurora. Any user can then bridge tokens via `ft_transfer_call`. There is no check that the NEP-141 token is non-rebasing or non-fee-on-transfer.

---

### Impact Explanation

- **Insolvency:** Aurora's NEP-141 custody balance falls below the ERC-20 total supply. The bridge is structurally insolvent for that token.
- **Without `error_refund`:** The last user(s) to call `withdrawToNear` have their ERC-20 tokens burned and receive nothing. This is **permanent freezing/destruction of user funds** (Critical).
- **With `error_refund`:** Burned ERC-20 tokens are re-minted via `refund_on_error`, but the underlying NEP-141 shortfall remains. No user can fully exit until the NEP-141 balance is externally restored. This is **temporary freezing of funds** (High).

---

### Likelihood Explanation

- `deploy_erc20_token` is permissionless; any NEP-141 token — including rebasing or fee-on-transfer tokens — can be registered.
- The NEAR ecosystem has no protocol-level restriction preventing rebasing NEP-141 tokens from existing.
- Once such a token is bridged and its balance decreases (even by a small rebase), the insolvency condition is active and the next `withdrawToNear` that exhausts the shortfall will fail.
- No special attacker capability is required beyond being a normal token holder.

---

### Recommendation

1. **Balance-check on deposit:** In `receive_erc20_tokens`, query Aurora's NEP-141 balance before and after the transfer (via a cross-contract call or by trusting only the delta), and mint ERC-20 tokens equal to the actual increase rather than `args.amount`.
2. **Token allowlist:** Restrict `deploy_erc20_token` to a curated set of standard NEP-141 tokens that are known to be non-rebasing and non-fee-on-transfer.
3. **Ensure `error_refund` is always compiled in** for production builds to at least prevent permanent ERC-20 destruction when `ft_transfer` fails, even if the underlying insolvency is not resolved.

---

### Proof of Concept

1. Deploy a rebasing NEP-141 token `rebase.near` on NEAR (total supply can decrease on rebase).
2. Call `deploy_erc20_token` on Aurora for `rebase.near` — permissionless, succeeds.
3. Alice calls `ft_transfer_call` on `rebase.near` with `amount = 1000`, transferring to Aurora. Aurora's `ft_on_transfer` is called; `receive_erc20_tokens` mints 1000 ERC-20 tokens for Alice. Aurora holds 1000 NEP-141 tokens.
4. The rebasing mechanism fires; Aurora's `rebase.near` balance drops to 900.
5. Alice calls `withdrawToNear(recipient, 1000)` on the ERC-20 contract. `_burn(Alice, 1000)` executes — Alice's ERC-20 balance is now 0.
6. `ExitToNear` precompile schedules `ft_transfer` on `rebase.near` for amount 1000. The call fails because Aurora only holds 900.
7. Without `error_refund`: `exit_to_near_precompile_callback` receives `refund: None`, does nothing. Alice has lost 1000 ERC-20 tokens and received 0 NEP-141 tokens — **permanent fund freeze**.

Key code references: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** engine/src/engine.rs (L803-837)
```rust
        let amount = args.amount.as_u128();
        // Parse message to determine recipient
        let mut recipient = {
            // The message should contain the recipient EOA address.
            let message = args.msg.strip_prefix("0x").unwrap_or(&args.msg);
            // Recipient - 40 characters (Address in hex without '0x' prefix)
            if message.len() < 40 {
                return Err(ParseOnTransferMessageError::WrongMessageFormat.into());
            }
            let mut address_bytes = [0; 20];
            hex::decode_to_slice(&message[..40], &mut address_bytes)
                .map_err(|_| ParseOnTransferMessageError::WrongMessageFormat)?;
            Address::from_array(address_bytes)
        };

        if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
            && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
        {
            recipient = fallback_address;
        }

        let erc20_token = get_erc20_from_nep141(&self.io, token)?;
        let erc20_admin_address = current_address(current_account_id);
        let result = self
            .call(
                &erc20_admin_address,
                &erc20_token,
                Wei::zero(),
                setup_receive_erc20_tokens_input(&recipient, amount),
                u64::MAX,
                Vec::new(), // TODO: are there values we should put here?
                Vec::new(),
                handler,
            )
            .and_then(submit_result_or_err)?;
```

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

**File:** engine/src/contract_methods/connector.rs (L80-90)
```rust
        let args: FtOnTransferArgs = read_json_args(&io)?;
        let result = if predecessor_account_id == get_connector_account_id(&io)? {
            engine.receive_base_tokens(&args)
        } else {
            engine.receive_erc20_tokens(
                &predecessor_account_id,
                &args,
                &current_account_id,
                handler,
            )
        };
```

**File:** engine/src/contract_methods/connector.rs (L231-242)
```rust
        } else if let Some(args) = args.refund {
            // Exit call failed; need to refund tokens
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;

            if !refund_result.status.is_ok() {
                return Err(errors::ERR_REFUND_FAILURE.into());
            }

            Some(refund_result)
        } else {
            None
        };
```
