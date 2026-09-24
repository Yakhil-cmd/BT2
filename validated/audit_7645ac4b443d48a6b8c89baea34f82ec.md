No vulnerability found for this question.

Based on extensive searching across the FRAME/`pallet-contracts`, `pallet-revive`, `pallet-balances`, `pallet-assets`, and XCM executor code, I found no analogous pattern where a gas/weight parameter is accepted by a function signature but silently dropped/unused before an inner transfer or call, causing an unexpected failure due to insufficient resources.

The original report's bug class — a `gas` parameter accepted by `SafeERC20.safeTransferFrom` but never forwarded into the low-level `call{gas: ...}`, causing the transfer to run with default/insufficient gas — is specific to Solidity's manual gas-forwarding semantics for low-level calls. Polkadot SDK's resource-accounting model works fundamentally differently: weight/gas limits are enforced by the runtime's dispatch and metering machinery itself (`GasMeter`, `WeightMeter`, `ResourceMeter`/`TransactionMeter`/`FrameMeter` in `substrate/frame/contracts/src/gas.rs` and `substrate/frame/revive/src/metering/`), not by an application-level function silently ignoring a caller-supplied resource parameter. Every weight/gas parameter I traced through pallet-contracts' `call` extrinsic [1](#0-0)  and pallet-revive's `call`/`eth_call` extrinsics [2](#0-1)  is properly threaded into the metering system (`new_nested`, `charge`, `absorb_nested`) that actually enforces the limit [3](#0-2) .

I also checked for FRAME-macro-level detection of unused/witness parameters feeding weight calculations — the framework already has a dedicated lint (`UncheckedWeightWitness`) that specifically warns when a call argument is unused (prefixed with `_`) yet influences the declared weight, which is the closest structural analog and is already mitigated by design [4](#0-3) .

No demonstrable, reachable instance of a caller-supplied gas/weight/resource parameter being silently discarded before a token transfer or contract call was found in production code.

### Citations

**File:** substrate/frame/contracts/src/wasm/runtime.rs (L1381-1402)
```rust
	fn call(
		ctx: _,
		memory: _,
		callee_ptr: u32,
		_callee_len: u32,
		gas: u64,
		value_ptr: u32,
		_value_len: u32,
		input_data_ptr: u32,
		input_data_len: u32,
		output_ptr: u32,
		output_len_ptr: u32,
	) -> Result<ReturnErrorCode, TrapReason> {
		ctx.call(
			memory,
			CallFlags::ALLOW_REENTRY,
			CallType::Call {
				callee_ptr,
				value_ptr,
				deposit_ptr: SENTINEL,
				weight: Weight::from_parts(gas, 0),
			},
```

**File:** substrate/frame/revive/src/lib.rs (L1176-1197)
```rust
		#[pallet::call_index(1)]
		#[pallet::weight(<T as Config>::WeightInfo::call().saturating_add(*weight_limit))]
		pub fn call(
			origin: OriginFor<T>,
			dest: H160,
			#[pallet::compact] value: BalanceOf<T>,
			weight_limit: Weight,
			#[pallet::compact] storage_deposit_limit: BalanceOf<T>,
			data: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			Self::ensure_non_contract_if_signed(&origin)?;
			let mut output = Self::bare_call(
				origin,
				dest,
				Pallet::<T>::convert_native_to_evm(value),
				TransactionLimits::WeightAndDeposit {
					weight_limit,
					deposit_limit: storage_deposit_limit,
				},
				data,
				&ExecConfig::new_substrate_tx(),
			);
```

**File:** substrate/frame/revive/src/metering/mod.rs (L160-202)
```rust
impl<T: Config, S: State> ResourceMeter<T, S> {
	/// Create a new nested meter with derived resource limits.
	pub fn new_nested(&self, limit: &CallResources<T>) -> Result<FrameMeter<T>, DispatchError> {
		log::trace!(
			target: LOG_TARGET,
			"Creating nested meter from parent: \
				limit={limit:?}, \
				weight_left={:?}, \
				deposit_left={:?}, \
				weight_consumed={:?}, \
				deposit_consumed={:?}",
			self.weight_left(),
			self.deposit_left(),
			self.weight_consumed(),
			self.deposit_consumed(),
		);

		let mut new_meter = match &self.transaction_limits {
			TransactionLimits::EthereumGas { eth_tx_info, .. } => {
				math::ethereum_execution::new_nested_meter(self, limit, eth_tx_info)
			},
			TransactionLimits::WeightAndDeposit { .. } => {
				math::substrate_execution::new_nested_meter(self, limit)
			},
		}?;

		new_meter.adjust_effective_weight_limit()?;

		log::trace!(
			target: LOG_TARGET,
			"Creating nested meter done: \
				weight_left={:?}, \
				deposit_left={:?}, \
				weight_consumed={:?}, \
				deposit_consumed={:?}",
			new_meter.weight_left(),
			new_meter.deposit_left(),
			new_meter.weight_consumed(),
			new_meter.deposit_consumed(),
		);

		Ok(new_meter)
	}
```

**File:** substrate/frame/support/procedural/src/pallet/expand/warnings.rs (L27-56)
```rust
/// Warn if any of the call arguments starts with a underscore and is used in a weight formula.
pub(crate) fn weight_witness_warning(
	method: &CallVariantDef,
	dev_mode: bool,
	warnings: &mut Vec<Warning>,
) {
	if dev_mode {
		return;
	}
	let CallWeightDef::Immediate(w) = &method.weight else { return };

	let partial_warning = Warning::new_deprecated("UncheckedWeightWitness")
		.old("not check weight witness data")
		.new("ensure that all witness data for weight calculation is checked before usage")
		.help_link("https://github.com/paritytech/polkadot-sdk/pull/1818");

	for (_, arg_ident, _) in method.args.iter() {
		if !arg_ident.to_string().starts_with('_') || !contains_ident(w.clone(), &arg_ident) {
			continue;
		}

		let warning = partial_warning
			.clone()
			.index(warnings.len())
			.span(arg_ident.span())
			.build_or_panic();

		warnings.push(warning);
	}
}
```
