No vulnerability found for this question.

This report describes an economic/gas-cost complaint specific to Ethereum's deployment-cost model (deploying `TimeswapPair` implicitly costs "thousands of dollars"), not a security vulnerability with a violated invariant, missing check, or exploitable state mutation. In the Polkadot SDK, contract instantiation via `pallet-contracts`/`pallet-revive` always requires the caller to explicitly supply `gas_limit`/`weight_limit` and `storage_deposit_limit` parameters up front [1](#0-0) [2](#0-1) , and instantiation from an existing `code_hash` (`Code::Existing`) versus fresh code upload (`Code::Upload`) is a decision the caller makes explicitly rather than something silently triggered as a side-effect of another action [3](#0-2) . There is no FRAME/XCM analog where a user's extrinsic silently and implicitly forces an expensive contract/pallet deployment without the caller's explicit weight/fee accounting and consent, so the "unwitting expensive deployment" root cause from the Timeswap finding does not have a demonstrable, reachable analog in this codebase. This class of finding (gas-only/economic cost complaint without a broken invariant) is explicitly excluded per the analysis rules.

### Citations

**File:** substrate/frame/contracts/src/lib.rs (L996-1004)
```rust
		pub fn instantiate_with_code(
			origin: OriginFor<T>,
			#[pallet::compact] value: BalanceOf<T>,
			gas_limit: Weight,
			storage_deposit_limit: Option<<BalanceOf<T> as codec::HasCompact>::Type>,
			code: Vec<u8>,
			data: Vec<u8>,
			salt: Vec<u8>,
		) -> DispatchResultWithPostInfo {
```

**File:** substrate/frame/revive/src/lib.rs (L1220-1228)
```rust
		pub fn instantiate(
			origin: OriginFor<T>,
			#[pallet::compact] value: BalanceOf<T>,
			weight_limit: Weight,
			#[pallet::compact] storage_deposit_limit: BalanceOf<T>,
			code_hash: sp_core::H256,
			data: Vec<u8>,
			salt: Option<[u8; 32]>,
		) -> DispatchResultWithPostInfo {
```

**File:** substrate/frame/revive/src/lib.rs (L1865-1912)
```rust
	pub fn bare_instantiate(
		origin: OriginFor<T>,
		evm_value: U256,
		transaction_limits: TransactionLimits<T>,
		code: Code,
		data: Vec<u8>,
		salt: Option<[u8; 32]>,
		exec_config: &ExecConfig<T>,
	) -> ContractResult<InstantiateReturnValue, BalanceOf<T>> {
		let mut transaction_meter = match TransactionMeter::new(transaction_limits) {
			Ok(transaction_meter) => transaction_meter,
			Err(error) => return ContractResult { result: Err(error), ..Default::default() },
		};

		let mut storage_deposit = Default::default();

		let try_instantiate = || {
			let instantiate_account = T::InstantiateOrigin::ensure_origin(origin.clone())?;

			if_tracing(|t| t.instantiate_code(&code, salt.as_ref()));
			let executable = match code {
				Code::Upload(code) if code.starts_with(&polkavm_common::program::BLOB_MAGIC) => {
					let upload_account = T::UploadOrigin::ensure_origin(origin)?;
					let executable = Self::try_upload_code(
						upload_account,
						code,
						BytecodeType::Pvm,
						&mut transaction_meter,
						&exec_config,
					)?;
					executable
				},
				Code::Upload(code) => {
					if T::AllowEVMBytecode::get() {
						ensure!(data.is_empty(), <Error<T>>::EvmConstructorNonEmptyData);
						let origin = T::UploadOrigin::ensure_origin(origin)?;
						let executable = ContractBlob::from_evm_init_code(code, origin)?;
						executable
					} else {
						return Err(<Error<T>>::CodeRejected.into());
					}
				},
				Code::Existing(code_hash) => {
					let executable = ContractBlob::from_storage(code_hash, &mut transaction_meter)?;
					ensure!(executable.code_info().is_pvm(), <Error<T>>::EvmConstructedFromHash);
					executable
				},
			};
```
