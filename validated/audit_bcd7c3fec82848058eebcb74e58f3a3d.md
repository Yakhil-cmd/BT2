### Title
ERC-20 Token Burn Without Refund Callback Permanently Freezes NEP-141 Funds When `ft_transfer` Fails - (File: `engine-precompiles/src/native.rs`)

### Summary

When the `error_refund` compile-time feature is disabled, the `ExitToNear` precompile burns a user's ERC-20 tokens in the EVM and dispatches a `ft_transfer` promise to the NEP-141 contract, but creates **no callback**. If the `ft_transfer` promise fails, the ERC-20 tokens are permanently destroyed while the corresponding NEP-141 tokens remain locked inside Aurora's account with no recovery path. This creates a permanent divergence between the EVM ERC-20 supply and the NEP-141 balance held by Aurora — the direct analog of the reported whitelist-table vs. contract-balance divergence.

---

### Finding Description

The `ExitToNear` precompile's `run` function constructs a `callback_args` struct and decides whether to attach a callback promise:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,                          // ← always None without the feature
    transfer_near: transfer_near_args,
};

let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)  // ← no callback attached
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { base: transfer_promise, callback: ... })
};
``` [1](#0-0) 

`ExitToNearPrecompileCallbackArgs::default()` is `{ refund: None, transfer_near: None }`. Without `error_refund`, `refund` is always `None`. For all standard ERC-20 exits (non-wNEAR-unwrap), `transfer_near` is also `None`. Therefore `callback_args == default()` evaluates to `true`, and **no callback is ever attached** to the `ft_transfer` promise.

The ERC-20 burn happens unconditionally inside `withdrawToNear` in `EvmErc20.sol` before the precompile is called:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    // calls ExitToNear precompile
}
``` [2](#0-1) 

If the subsequent `ft_transfer` promise fails (recipient not registered, NEP-141 paused, gas exhaustion, etc.), the EVM ERC-20 supply has been permanently reduced while the NEP-141 tokens remain in Aurora's account. The `exit_to_near_precompile_callback` is never invoked, so `refund_on_error` is never called:

```rust
} else if let Some(args) = args.refund {
    // Only reached when error_refund is enabled
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
    ...
} else {
    None  // ← reached when error_refund is disabled; no refund, no re-mint
};
``` [3](#0-2) 

The test suite explicitly acknowledges this divergence:

```rust
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [4](#0-3) 

---

### Impact Explanation

**Impact: Critical — Permanent freezing of funds.**

When `error_refund` is not compiled in:

- The user's ERC-20 tokens are burned (EVM supply decreases).
- The NEP-141 tokens remain locked in Aurora's account (NEP-141 balance unchanged).
- There is no re-mint, no callback, and no recovery path.
- The NEP-141 tokens are permanently inaccessible: the ERC-20 tokens needed to "exit again" no longer exist.

This is structurally identical to the reported bug: one accounting ledger (EVM ERC-20 supply) records a reduction that the other ledger (NEP-141 balance held by Aurora) does not reflect, leaving real tokens permanently frozen.

---

### Likelihood Explanation

**Likelihood: Medium (conditional on build configuration).**

The `error_refund` feature is a compile-time flag. `EvmErc20V2.sol` encodes the refund address in its calldata (`abi.encodePacked("\x01", sender, amount_b, recipient)`), which is only correctly parsed when `error_refund` is enabled; without it, the 20-byte sender field is misread as part of the amount, making `EvmErc20V2.sol` incompatible with a non-`error_refund` build. [5](#0-4) 

However, the legacy `EvmErc20.sol` (still present and deployable) is only compatible with the non-`error_refund` build. Any deployment using `EvmErc20.sol` without `error_refund` is fully exposed. Additionally, the `ft_transfer` failure condition is reachable by any unprivileged user who exits to an unregistered NEAR account — a common user mistake.

---

### Recommendation

1. **Unconditionally attach the callback**: Remove the `#[cfg(not(feature = "error_refund"))] refund: None` branch and always populate `refund` with the necessary data to re-mint tokens on failure. The callback cost is negligible compared to the risk of permanent fund loss.
2. **Deprecate `EvmErc20.sol`**: Enforce use of `EvmErc20V2.sol` (which includes the refund address) and make `error_refund` a mandatory, always-on feature rather than an optional compile flag.
3. **Validate recipient registration before burning**: Before burning ERC-20 tokens, verify (via a view call or storage check) that the NEAR recipient is registered with the NEP-141 contract, preventing the failure scenario entirely.

---

### Proof of Concept

1. Deploy Aurora Engine **without** the `error_refund` feature flag.
2. Bridge a NEP-141 token to Aurora (ERC-20 minted via `ft_on_transfer` → `receive_erc20_tokens`).
3. Call `withdrawToNear(recipient_bytes, amount)` on the ERC-20 contract where `recipient` is a NEAR account **not registered** with the NEP-141 contract.
4. The ERC-20 `_burn` executes; the `ExitToNear` precompile fires a bare `ft_transfer` promise with no callback.
5. The `ft_transfer` fails (unregistered recipient).
6. Observe: ERC-20 balance is zero; NEP-141 balance of Aurora is unchanged; user's funds are permanently frozen.

The test `test_exit_to_near_refund` in `engine-tests/src/tests/erc20_connector.rs` (lines 623–665) reproduces exactly this scenario and confirms the balance divergence under `#[cfg(not(feature = "error_refund"))]`. [6](#0-5)

### Citations

**File:** engine-precompiles/src/native.rs (L449-483)
```rust
        let callback_args = ExitToNearPrecompileCallbackArgs {
            #[cfg(feature = "error_refund")]
            refund: refund_call_args(&exit_to_near_params, &exit_event),
            #[cfg(not(feature = "error_refund"))]
            refund: None,
            transfer_near: transfer_near_args,
        };
        let attached_gas = if method == "ft_transfer_call" {
            costs::FT_TRANSFER_CALL_GAS
        } else {
            costs::FT_TRANSFER_GAS
        };

        let transfer_promise = PromiseCreateArgs {
            target_account_id: nep141_address,
            method,
            args: args.into_bytes(),
            attached_balance: Yocto::new(1),
            attached_gas,
        };

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

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-60)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;

        assembly {
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

**File:** engine-tests/src/tests/erc20_connector.rs (L623-665)
```rust
    #[tokio::test]
    async fn test_exit_to_near_refund() {
        // Deploy Aurora; deploy NEP-141; bridge NEP-141 to ERC-20 on Aurora
        let TestExitToNearContext {
            ft_owner,
            ft_owner_address,
            nep_141,
            erc20,
            aurora,
            ..
        } = test_exit_to_near_common().await.unwrap();

        // Call exit on ERC-20; ft_transfer promise fails; expect refund on Aurora;
        exit_to_near(
            &ft_owner,
            // The ft_transfer will fail because this account is not registered with the NEP-141
            "unregistered.near",
            FT_EXIT_AMOUNT,
            &erc20,
            &aurora,
        )
        .await
        .unwrap();

        assert_eq!(
            nep_141_balance_of(&nep_141, &ft_owner.id()).await,
            FT_TOTAL_SUPPLY - FT_TRANSFER_AMOUNT
        );
        assert_eq!(
            nep_141_balance_of(&nep_141, &aurora.id()).await,
            FT_TRANSFER_AMOUNT
        );

        #[cfg(feature = "error_refund")]
        let balance = FT_TRANSFER_AMOUNT.into();
        // If the refund feature is not enabled then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();

        assert_eq!(
            erc20_balance(&erc20, ft_owner_address, &aurora).await,
            balance
        );
```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L53-64)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        address sender = _msgSender();
        _burn(sender, amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
        uint input_size = 1 + 20 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
    }
```
