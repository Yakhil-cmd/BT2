### Title
XCC Precompile ERC-20 `transferFrom` Missing Return Value Check — (`engine-precompiles/src/xcc.rs`)

### Summary

The Cross-Contract Call (XCC) precompile calls `transferFrom` on the wNEAR ERC-20 contract to collect the required NEAR payment from the caller, but only checks whether the EVM sub-call's exit reason is `Succeed`. It never decodes or validates the `bool` return value of `transferFrom`. If the wNEAR contract returns `false` instead of reverting on a failed transfer, the precompile silently proceeds, emitting the promise log and scheduling the cross-contract call without the required NEAR having been collected.

### Finding Description

In `engine-precompiles/src/xcc.rs`, `run_with_handle` builds a `transferFrom` calldata payload and executes it via `handle.call`: [1](#0-0) 

The destructured `return_value` is the ABI-encoded `bool` that ERC-20's `transferFrom` returns. The `match` on `exit_reason` only handles `Revert`, `Error`, and `Fatal` as failures. When `exit_reason` is `Succeed`, the code does nothing — `return_value` is completely ignored. No decoding of the 32-byte boolean payload is performed.

The `transfer_from_args` helper encodes the standard `transferFrom(address,address,uint256)` selector `0x23b872dd`: [2](#0-1) 

The project's own test fixture even documents that `transferFrom` returns a `bool`: [3](#0-2) 

After the unchecked call, the precompile unconditionally emits the promise log: [4](#0-3) 

### Impact Explanation

**High — Temporary freezing of funds / insolvency.**

If the wNEAR ERC-20 contract's `transferFrom` returns `false` (e.g., insufficient balance or allowance, non-standard implementation, or a future contract upgrade), the XCC precompile proceeds as if the payment succeeded. The promise log is emitted and the engine schedules `withdraw_wnear_to_router`. Because the wNEAR was never actually moved to the engine's implicit address, the subsequent `withdraw_wnear_to_router` call will fail or draw from wNEAR already held by the engine's implicit address from other users' deposits — effectively using other users' funds to cover the attacker's cross-contract call. This constitutes either a temporary freeze of the cross-contract call (failed NEAR-side execution) or direct misappropriation of other users' wNEAR balances held in the engine's implicit address.

### Likelihood Explanation

**Medium.** The wNEAR contract is an external ERC-20 whose implementation can be upgraded or replaced. Any non-standard wNEAR that returns `false` on failure (rather than reverting) — a well-known pattern in older or non-OpenZeppelin ERC-20 tokens — triggers this path. Any EVM user who can call the XCC precompile is an unprivileged attacker-controlled entry point.

### Recommendation

After the `Succeed` arm, decode `return_value` as an ABI-encoded `bool` and revert if it is `false`:

```rust
aurora_evm::ExitReason::Succeed(_) => {
    // ERC-20 transferFrom returns a bool; false means the transfer failed.
    let success = return_value.last().copied().unwrap_or(0) != 0;
    if !success {
        return Err(revert_with_message("ERR_WNEAR_TRANSFER_FROM_FAILED"));
    }
}
```

This mirrors the `safeTransferFrom` pattern recommended in the original M-04 report.

### Proof of Concept

1. Deploy a wNEAR ERC-20 whose `transferFrom` always returns `false` without reverting (non-standard but valid ERC-20 behavior).
2. Register it as the wNEAR address in the engine via `factory_set_wnear_address`.
3. Call the XCC precompile (`0x516cded1d16af10cad47d6d49128e2eb7d27b372`) with a valid `CrossContractCallArgs::Eager` payload and `required_near > 0`.
4. Observe: `exit_reason` is `Succeed`, `return_value` is `0x00…00` (false), but the precompile returns `Ok(PrecompileOutput { logs: [promise_log], … })` — no revert.
5. The engine processes the promise log and schedules `withdraw_wnear_to_router` for `required_near` yoctoNEAR from the engine's implicit address, despite no wNEAR having been transferred from the caller. [5](#0-4)

### Citations

**File:** engine-precompiles/src/xcc.rs (L183-217)
```rust
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

**File:** engine-precompiles/src/xcc.rs (L219-237)
```rust
        let topics = vec![
            cross_contract_call::AMOUNT_TOPIC,
            H256(aurora_engine_types::types::u256_to_arr(&U256::from(
                required_near.as_u128(),
            ))),
        ];

        let promise_log = Log {
            address: cross_contract_call::ADDRESS.raw(),
            topics,
            data: borsh::to_vec(&promise)
                .map_err(|_| ExitError::Other(Cow::from(consts::ERR_SERIALIZE)))?,
        };

        Ok(PrecompileOutput {
            logs: vec![promise_log],
            cost,
            ..Default::default()
        })
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

**File:** engine-precompiles/src/xcc.rs (L362-366)
```rust
            outputs: vec![ethabi::Param {
                name: String::new(),
                kind: ethabi::ParamType::Bool,
                internal_type: None,
            }],
```
