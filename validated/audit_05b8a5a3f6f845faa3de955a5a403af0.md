### Title
Unchecked `transferFrom` Return Value in XCC Precompile Allows NEAR Payment Bypass - (File: `engine-precompiles/src/xcc.rs`)

### Summary
The Cross-Contract Call (XCC) precompile calls `transferFrom` on the wNEAR ERC-20 contract to collect NEAR payment from the caller before scheduling a cross-contract call. The EVM-level exit reason is checked, but the ABI-encoded `bool` return value of `transferFrom` is captured and then silently discarded on success. If the wNEAR token returns `false` instead of reverting on a failed transfer, the precompile proceeds as if payment was received, allowing the engine's own NEAR balance to fund cross-contract calls without compensation.

### Finding Description

In `engine-precompiles/src/xcc.rs`, when a cross-contract call requires NEAR payment (either for storage staking or attached balance), the precompile calls `transferFrom` on the wNEAR ERC-20 contract:

```rust
let (exit_reason, return_value) =
    handle.call(wnear_address.raw(), None, tx_data, None, false, &context);
match exit_reason {
    aurora_evm::ExitReason::Succeed(_) => (),   // ← return_value never inspected
    ...
}
``` [1](#0-0) 

The `return_value` bytes — which carry the ABI-encoded `bool` result of `transferFrom` — are only forwarded in the `Revert` branch. In the `Succeed` branch they are dropped entirely. [2](#0-1) 

The calldata is constructed with the standard `transferFrom` selector `0x23b872dd`: [3](#0-2) 

and encoded via: [4](#0-3) 

The ERC-20 standard permits a compliant token to return `false` on failure rather than reverting. In that case the EVM sub-call exits with `ExitReason::Succeed`, the `return_value` is 32 bytes of zeros (`false`), and the match arm `Succeed(_) => ()` silently continues — no payment is actually collected.

### Impact Explanation

**Critical — Insolvency / Permanent fund freeze.**

When `required_near` is non-zero (new router deployment costs `STORAGE_AMOUNT = 2 × 10²⁴ yoctoNEAR` plus any attached balance), the engine is expected to receive wNEAR from the caller before forwarding NEAR to the router. If the `transferFrom` silently fails, the engine's own NEAR reserve is consumed to fund the router deployment and the cross-contract call, with no corresponding debit from the caller. Repeated exploitation drains the engine's NEAR balance to zero, making it unable to pay for future operations — insolvency. [5](#0-4) 

### Likelihood Explanation

**Medium.** The wNEAR address is set by the operator via `factory_set_wnear_address`. The canonical wNEAR contract is an OpenZeppelin-derived ERC-20 that reverts on failure, so the default deployment is not immediately vulnerable. However:

1. The code makes no assumption about wNEAR's revert-vs-return-false behavior — it is architecturally unsound regardless.
2. Any future wNEAR upgrade or alternative deployment that follows the non-reverting ERC-20 pattern (e.g., USDT-style) would immediately expose this path.
3. An unprivileged EVM user with zero wNEAR allowance can call the XCC precompile directly; the only gate is whether `transferFrom` reverts or returns `false`.

### Recommendation

Decode and assert the boolean return value after a `Succeed` exit, mirroring the SafeERC20 pattern:

```rust
aurora_evm::ExitReason::Succeed(_) => {
    // Decode the ABI bool return value; treat false as a revert.
    let success = return_value.last().copied().unwrap_or(0) != 0;
    if !success {
        return Err(revert_with_message("ERR_WNEAR_TRANSFER_FROM_FAILED"));
    }
}
```

This ensures that a `false` return from `transferFrom` is treated as a failed transfer, preventing the precompile from proceeding without actual payment.

### Proof of Concept

1. Deploy a wNEAR-compatible ERC-20 whose `transferFrom` always returns `false` instead of reverting (valid per ERC-20 spec).
2. Set this contract as the wNEAR address via `factory_set_wnear_address`.
3. Call the XCC precompile (`0x516cded1d16af10cad47d6d49128e2eb7d27b372`) with a `CrossContractCallArgs::Eager` payload that attaches NEAR.
4. The precompile calls `transferFrom` → EVM exits `Succeed` with `return_value = [0x00…00]` → match arm `Succeed(_) => ()` fires → precompile continues.
5. The cross-contract call is scheduled and the engine's NEAR balance is debited; the caller's wNEAR balance is unchanged.
6. Repeat until the engine's NEAR balance is exhausted → insolvency. [6](#0-5)

### Citations

**File:** engine-precompiles/src/xcc.rs (L60-63)
```rust
    /// Solidity selector for the ERC-20 transferFrom function
    /// `https://www.4byte.directory/signatures/?bytes4_signature=0x23b872dd`
    pub(super) const TRANSFER_FROM_SELECTOR: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
}
```

**File:** engine-precompiles/src/xcc.rs (L177-217)
```rust
        let required_near =
            match state::get_code_version_of_address(&self.io, &Address::new(sender)) {
                // If there is no deployed version of the router contract then we need to charge for storage staking
                None => attached_near + state::STORAGE_AMOUNT,
                Some(_) => attached_near,
            };
        // if some NEAR payment is needed, transfer it from the caller to the engine's implicit address
        if required_near != ZERO_YOCTO {
            let engine_implicit_address = aurora_engine_sdk::types::near_account_to_evm_address(
                self.engine_account_id.as_bytes(),
            );
            let tx_data = transfer_from_args(
                sender.0.into(),
                engine_implicit_address.raw().0.into(),
                required_near.as_u128().into(),
            );
            let wnear_address = state::get_wnear_address(&self.io);
            let context = aurora_evm::Context {
                address: wnear_address.raw(),
                caller: cross_contract_call::ADDRESS.raw(),
                apparent_value: U256::zero(),
            };
            let (exit_reason, return_value) =
                handle.call(wnear_address.raw(), None, tx_data, None, false, &context);
            match exit_reason {
                // Transfer successful, nothing to do
                aurora_evm::ExitReason::Succeed(_) => (),
                aurora_evm::ExitReason::Revert(r) => {
                    return Err(PrecompileFailure::Revert {
                        exit_status: r,
                        output: return_value,
                    });
                }
                aurora_evm::ExitReason::Error(e) => {
                    return Err(PrecompileFailure::Error { exit_status: e });
                }
                aurora_evm::ExitReason::Fatal(f) => {
                    return Err(PrecompileFailure::Fatal { exit_status: f });
                }
            }
        }
```

**File:** engine-precompiles/src/xcc.rs (L292-299)
```rust
fn transfer_from_args(from: ethabi::Address, to: ethabi::Address, amount: ethabi::Uint) -> Vec<u8> {
    let args = ethabi::encode(&[
        ethabi::Token::Address(from),
        ethabi::Token::Address(to),
        ethabi::Token::Uint(amount),
    ]);
    [&consts::TRANSFER_FROM_SELECTOR, args.as_slice()].concat()
}
```
