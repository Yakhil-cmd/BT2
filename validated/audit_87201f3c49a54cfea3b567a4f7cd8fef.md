### Title
Unchecked `transferFrom` Return Value in XCC Precompile Allows Free Cross-Contract Calls - (File: engine-precompiles/src/xcc.rs)

### Summary
The cross-contract call (XCC) precompile calls `transferFrom` on the wNEAR ERC-20 contract to collect payment from the caller before scheduling a NEAR cross-contract call. The EVM sub-call's exit reason is checked, but the ABI-encoded boolean return value of `transferFrom` is never decoded or validated. If the wNEAR contract returns `false` without reverting, the precompile silently proceeds, emitting the promise log and triggering the cross-contract call without the engine having received the required wNEAR payment.

### Finding Description
In `engine-precompiles/src/xcc.rs`, when `required_near != ZERO_YOCTO`, the precompile constructs a `transferFrom(sender, engine_implicit_address, amount)` calldata and executes it against the wNEAR ERC-20 contract via `handle.call(...)`. [1](#0-0) 

The result is destructured as `(exit_reason, return_value)`. The `match` on `exit_reason` handles `Revert`, `Error`, and `Fatal` by propagating failures, and treats `Succeed(_)` as unconditional success:

```rust
aurora_evm::ExitReason::Succeed(_) => (),
```

The `return_value` — which contains the ABI-encoded `bool` returned by `transferFrom` — is **never decoded or inspected** in the `Succeed` branch. A conforming ERC-20 `transferFrom` that returns `false` (without reverting) would cause the precompile to proceed past the payment step as if the transfer succeeded. [2](#0-1) 

The `transfer_from_args` helper correctly encodes the `transferFrom(address,address,uint256)` selector and arguments, confirming this is a real ERC-20 call whose boolean return is expected but ignored. [3](#0-2) 

### Impact Explanation
**Critical — Insolvency / Direct theft of funds in motion.**

If `transferFrom` returns `false` without reverting, the engine emits the `promise_log` that schedules a NEAR cross-contract call funded from the engine's own NEAR balance, while the caller's wNEAR balance is never debited. An attacker can repeatedly invoke the XCC precompile, draining the engine's NEAR reserve to fund arbitrary cross-contract calls at zero cost. This constitutes direct theft of the engine's NEAR funds and leads to insolvency of the engine contract.

### Likelihood Explanation
**Medium.** The current production wNEAR contract is based on OpenZeppelin ERC-20, which reverts on failure rather than returning `false`. However:
1. The wNEAR address is read dynamically from storage (`state::get_wnear_address`), meaning a governance/admin action that updates the wNEAR address to a non-reverting token would immediately expose this path.
2. Any future upgrade or replacement of the wNEAR contract with a non-reverting variant (e.g., USDT-style) would make this trivially exploitable by any EVM user who calls the XCC precompile.
3. The code pattern itself is incorrect regardless of the current wNEAR behavior.

### Recommendation
After the `Succeed` branch, decode `return_value` as an ABI-encoded `bool` and revert if it is `false`:

```rust
aurora_evm::ExitReason::Succeed(_) => {
    // ERC-20 transferFrom returns a bool; false means transfer failed silently
    let success = return_value.last().copied().unwrap_or(0) != 0;
    if !success {
        return Err(revert_with_message("ERR_WNEAR_TRANSFER_FAILED"));
    }
}
```

Alternatively, use a wNEAR implementation that always reverts on failure (OpenZeppelin standard), and add an explicit assertion here as a defense-in-depth measure.

### Proof of Concept
1. Deploy or configure a wNEAR ERC-20 contract that returns `false` from `transferFrom` instead of reverting (e.g., a USDT-style non-reverting token, or a mock).
2. Update the engine's wNEAR address in storage to point to this contract (or wait for a governance update).
3. Call the XCC precompile from any EVM address with a valid `CrossContractCallArgs` payload requiring NEAR payment.
4. The precompile calls `transferFrom(attacker, engine_implicit_address, amount)` → wNEAR returns `false` without reverting → `exit_reason` is `Succeed` → `return_value` (`0x...00` = `false`) is ignored.
5. The precompile emits the `promise_log` at line 226–231, scheduling the cross-contract call funded by the engine's NEAR balance.
6. The attacker's wNEAR balance is unchanged; the engine's NEAR is spent. Repeat to drain the engine. [4](#0-3)

### Citations

**File:** engine-precompiles/src/xcc.rs (L184-237)
```rust
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
