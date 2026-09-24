No vulnerability found for this question.

The analog bug class here—unbounded external-call return data causing gas/resource exhaustion before state (a "forwarded" flag) can be persisted—does not reproduce in `pallet-revive`. The pallet already implements the exact safeguard the report recommends: return data size is capped by `limits::CALLDATA_BYTES` and enforced in `seal_return`, which errors with `ReturnDataTooLarge` if the contract-supplied `data_len` exceeds the limit, and gas is charged proportionally to the copied length before the copy occurs via `RuntimeCosts::CopyFromContract(data_len)` [1](#0-0) . The same bound is enforced on the inter-contract `call`/`delegate_call` path where input and output data lengths are checked against `limits::CALLDATA_BYTES` (`CallDataTooLarge`) and every byte copied to/from contract memory is metered before the copy happens [2](#0-1) . This mirrors the report's own "short-term" recommendation (bound the return data size) already being first-class pallet behavior rather than a missing check.

Structurally, this also breaks the analogy the report relies on: FRAME extrinsic dispatch is not analogous to the vulnerable "relayer retries an off-chain forwarding queue" pattern—there is no `forwarded[id]` style flag left un-set by an out-of-gas host call that a caller can keep re-submitting for free; weight/fees are pre-charged per dispatch and `pallet-revive` enforces upfront calldata/output-size limits (`CallDataTooLarge`, `ReturnDataTooLarge` in `Error` enum) rather than relying on an unbounded low-level call return buffer [3](#0-2) . Additionally, this class of finding (generic resource-exhaustion / oversized-return-data / gas-only concern) is explicitly excluded from scope per the scan's rejection criteria, and no attacker-reachable FRAME/XCM entry point exhibits the missing check described in the source report.

### Citations

**File:** substrate/frame/revive/src/vm/pvm/env.rs (L538-544)
```rust
	) -> Result<(), TrapReason> {
		self.charge_gas(RuntimeCosts::CopyFromContract(data_len))?;
		if data_len > limits::CALLDATA_BYTES {
			Err(<Error<E::T>>::ReturnDataTooLarge)?;
		}
		Err(TrapReason::Return(ReturnData { flags, data: memory.read(data_ptr, data_len)? }))
	}
```

**File:** substrate/frame/revive/src/vm/pvm.rs (L649-678)
```rust
	) -> Result<ReturnErrorCode, TrapReason> {
		let callee = memory.read_h160(callee_ptr)?;
		let precompile = <AllPrecompiles<E::T>>::get::<E>(&callee.as_fixed_bytes());
		match &precompile {
			Some(precompile) if precompile.has_contract_info() => {
				self.charge_gas(RuntimeCosts::PrecompileWithInfoBase)?
			},
			Some(_) => self.charge_gas(RuntimeCosts::PrecompileBase)?,
			None => self.charge_gas(call_type.cost())?,
		};

		// we do check this in exec.rs but we want to error out early
		if input_data_len > limits::CALLDATA_BYTES {
			Err(<Error<E::T>>::CallDataTooLarge)?;
		}

		let input_data = if flags.contains(CallFlags::CLONE_INPUT) {
			let input = self.input_data.as_ref().ok_or(Error::<E::T>::InputForwarded)?;
			charge_gas!(self, RuntimeCosts::CallInputCloned(input.len() as u32))?;
			input.clone()
		} else if flags.contains(CallFlags::FORWARD_INPUT) {
			self.input_data.take().ok_or(Error::<E::T>::InputForwarded)?
		} else {
			if precompile.is_some() {
				self.charge_gas(RuntimeCosts::PrecompileDecode(input_data_len))?;
			} else {
				self.charge_gas(RuntimeCosts::CopyFromContract(input_data_len))?;
			}
			memory.read(input_data_ptr, input_data_len)?
		};
```

**File:** substrate/frame/revive/src/lib.rs (L619-624)
```rust
		/// Unsupported precompile address.
		UnsupportedPrecompileAddress = 0x2F,
		/// The calldata exceeds [`limits::CALLDATA_BYTES`].
		CallDataTooLarge = 0x30,
		/// The return data exceeds [`limits::CALLDATA_BYTES`].
		ReturnDataTooLarge = 0x31,
```
