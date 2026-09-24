### Title
Native `value` sent to a contract-info-less pre-compile (e.g. ERC20 asset pre-compile) is transferred unconditionally and can become permanently locked - ([File: substrate/frame/revive/src/exec.rs])

### Summary
`pallet_revive::Pallet::call` lets a signed caller specify a `dest` address and an arbitrary native-currency `value` independently of the ABI-encoded `data` payload, exactly like Solidity's `msg.value` alongside a function call. When `dest` resolves to a pre-compile that is declared with `HAS_CONTRACT_INFO = false` (e.g. the `ERC20` asset pre-compile wired into `asset-hub-westend` runtime), the pallet still unconditionally moves the attacker/caller-supplied `value` into the account derived from that pre-compile's fixed address, even though the pre-compile's own logic (e.g. `ERC20::transfer`) never reads or forwards `value_transferred`. Because such pre-compiles are documented to create "No account or any other state ... for the address," there is no code path that can move that balance back out, so the attached value is effectively burned/locked at an address nobody can spend from.

### Finding Description
`Pallet::call` accepts `value: BalanceOf<T>` as an explicit, user-controlled parameter alongside `dest` and `data`: [1](#0-0) 

Inside `exec.rs`, for any non-delegate call/instantiate frame, the native transfer of `value_transferred` is performed unconditionally before the callee logic (contract or pre-compile) even runs, with no check on whether the destination is a pre-compile lacking contract info: [2](#0-1) 

Only pre-compiles with `HAS_CONTRACT_INFO = true` get an account minted/created for them on demand; the account-existence-and-mint logic is gated behind that flag: [3](#0-2) 

The `Precompile::HAS_CONTRACT_INFO` documentation is explicit that when set to `false`, "No account or any other state will be created for the address," implying no balance-tracking/refund logic exists there: [4](#0-3) 

The `ERC20` pre-compile (`HAS_CONTRACT_INFO: bool = false`) used on Asset Hub for `transfer`/`transferFrom`/etc. never inspects or refunds `env.value_transferred()`; it only moves the ERC20/asset balance via `pallet_assets::do_transfer`, ignoring any native currency attached to the call: [5](#0-4) [6](#0-5) 

This mirrors the reported EVM pattern exactly: a "payable"-style entry point (`Pallet::call` with a `value` parameter) accepts an amount of native currency in addition to an ERC20-style `amount` argument encoded in `data`, but nothing validates that `value == 0` when the target function only deals in ERC20/asset amounts. As in the `InsurancePool.depositCollateral` bug, the caller's own excess "msg.value" analog is silently swallowed by a code path that was never designed to receive or account for it.

### Impact Explanation
Any signed caller who calls the runtime's `pallet_revive::Pallet::call` (or the underlying `bare_call`) against a fixed/prefix-matched pre-compile address with `HAS_CONTRACT_INFO = false` (any asset ERC20 pre-compile instance configured on Asset Hub, e.g. `ERC20<Self, InlineIdConfig<{TRUST_BACKED_ASSETS_PRECOMPILE}>, ...>`) while also setting a non-zero `value`, will have that native balance moved to the account keyed by the pre-compile's deterministic address. Per the trait documentation, no account/contract-info state is created for such addresses, so there is no mechanism (constructor, `receive`, withdrawal function, or storage entry) capable of moving that balance back out. The funds are effectively unrecoverable — a loss-of-user-funds bug reachable by any ordinary signed extrinsic, no privilege required.

### Likelihood Explanation
This is trivially reachable by any account with a signing key and a small balance: dispatch `pallet_revive::Pallet::call(origin, dest=<erc20_precompile_address>, value=<nonzero>, weight_limit, storage_deposit_limit, data=<ERC20 transfer/transferFrom call data>)`. No governance, no privileged origin, no malicious peer is needed — only user error or a wallet/dApp integration bug that naively attaches native value to an ERC20 call, exactly analogous to how the original report describes a UI/integration mistake leading to lost `msg.value`. Given ERC20 pre-compiles are live on Asset Hub Westend's `pallet_revive::Config`, the surface exists in a real runtime configuration.

### Recommendation
In `exec.rs`'s call-frame setup, reject (or refund) any non-zero `value_transferred` when the resolved executable is a pre-compile with `HAS_CONTRACT_INFO = false`, i.e., add a check next to the existing `if frame.delegate.is_none() { Self::transfer_from_origin(...) }` path that returns an error (e.g. a new `Error::<T>::PrecompileValueNotAllowed`) whenever `executable.as_precompile()` resolves to a contract-info-less pre-compile and `frame.value_transferred` is non-zero, mirroring the pattern already used for `StateChangeDenied` on read-only calls with non-zero value in the interpreter (`substrate/frame/revive/src/vm/pvm.rs:686-696`).

### Proof of Concept
I was not able to execute a live Rust/FRAME integration test in this environment (read-only analysis tools only), so the following describes the exact reproduction path but its execution status is **not verified end-to-end**:

1. Deploy/enable the `asset-hub-westend` runtime configuration where `pallet_revive::Config::Precompiles` includes `ERC20<Self, InlineIdConfig<{TRUST_BACKED_ASSETS_PRECOMPILE}>, TrustBackedAssetsInstance>` (`HAS_CONTRACT_INFO = false`), as wired in: [7](#0-6) 
2. As a normal signed account with sufficient native balance and an asset balance, call `pallet_revive::Pallet::call` with `dest` = the ERC20 pre-compile address, `value` = e.g. 1000 (native), and `data` = ABI-encoded `IERC20::transferCall{to, value: <asset amount>}`.
3. Observe (expected, based on code trace above) that: (a) the ERC20 asset `transfer` succeeds and emits `Transfer`; (b) the 1000 native `value` is moved via `transfer_from_origin` to the `AccountId` mapped from the pre-compile's fixed address; (c) no follow-up call, event, or storage item in `precompiles.rs`/`exec.rs` allows recovering that native balance since the address is documented to hold "no account or any other state."
4. This would need to be confirmed with an actual test harness invocation (e.g. extending `substrate/frame/assets/precompiles/src/tests.rs::precompile_transfer_works` to additionally pass a non-zero native `value` in the `bare_call` and assert the caller's/pre-compile-account's balances), which I could not run here.

Given the inability to execute this reproduction, treat the guard-check gap (unconditional `transfer_from_origin` regardless of `HAS_CONTRACT_INFO`) as the concrete, cited root cause, and confirm actual fund loss via the test harness before triaging severity beyond Medium.

### Citations

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

**File:** substrate/frame/revive/src/exec.rs (L1451-1463)
```rust
			// Every non delegate call or instantiate also optionally transfers the balance.
			// If it is a delegate call, then we've already transferred tokens in the
			// last non-delegate frame.
			if frame.delegate.is_none() {
				Self::transfer_from_origin(
					&self.origin,
					&caller,
					account_id,
					frame.value_transferred,
					&mut frame.frame_meter,
					self.exec_config,
				)?;
			}
```

**File:** substrate/frame/revive/src/exec.rs (L1465-1481)
```rust
			// We need to make sure that the pre-compiles contract exist before executing it.
			// A few more conditionals:
			// 	- Only contracts with extended API (has_contract_info) are guaranteed to have an
			//    account.
			//  - Only when not delegate calling we are executing in the context of the pre-compile.
			//    Pre-compiles itself cannot delegate call.
			if let Some(precompile) = executable.as_precompile() &&
				precompile.has_contract_info() &&
				frame.delegate.is_none() &&
				!<System<T>>::account_exists(account_id)
			{
				// prefix matching pre-compiles cannot have a contract info
				// hence we only mint once per pre-compile
				T::Currency::mint_into(account_id, T::Currency::minimum_balance())?;
				// make sure the pre-compile does not destroy its account by accident
				<System<T>>::inc_consumers(account_id)?;
			}
```

**File:** substrate/frame/revive/src/precompiles.rs (L190-221)
```rust
	/// # When set to **true**
	///
	/// - An account will be created at the pre-compiles address when it is called for the first
	///   time. The ed is minted.
	/// - Contract info data structure will be created in storage on first call.
	/// - Only `call_with_info` should be implemented. `call` is never called.
	///
	/// # When set to **false**
	///
	/// - No account or any other state will be created for the address.
	/// - Only `call` should be implemented. `call_with_info` is never called.
	///
	/// # What to use
	///
	/// Should be set to false if the additional functionality is not needed. A pre-compile with
	/// contract info will incur both a storage read and write to its contract metadata when called.
	///
	/// The contract info enables additional functionality:
	/// - Storage deposits: Collect deposits from the origin rather than the caller. This makes it
	///   easier for contracts to interact with the pre-compile as deposits
	/// 	are paid by the transaction signer (just like gas). It also makes refunding easier.
	/// - Contract storage: You can use the contracts key value child trie storage instead of
	///   providing your own state.
	/// 	The contract storage automatically takes care of deposits.
	/// 	Providing your own storage and using pallet_revive to collect deposits is also possible,
	/// though.
	/// - Instantitation: Contract instantiation requires the instantiator to have an account. This
	/// 	is because its nonce is used to derive the new contracts account id and child trie id.
	///
	/// Have a look at [`ExtWithInfo`] to learn about the additional APIs that a contract info
	/// unlocks.
	const HAS_CONTRACT_INFO: bool;
```

**File:** substrate/frame/assets/precompiles/src/lib.rs (L147-161)
```rust
impl<Runtime, PrecompileConfig, Instance: 'static> Precompile
	for ERC20<Runtime, PrecompileConfig, Instance>
where
	PrecompileConfig: AssetPrecompileConfig,
	Runtime: crate::Config<Instance> + pallet_revive::Config + permit::Config,
	<<PrecompileConfig as AssetPrecompileConfig>::AssetIdExtractor as AssetIdExtractor>::AssetId:
		Into<<Runtime as Config<Instance>>::AssetId>,
	Call<Runtime, Instance>: Into<<Runtime as pallet_revive::Config>::RuntimeCall>,
	alloy::primitives::U256: TryInto<<Runtime as Config<Instance>>::Balance>,
	alloy::primitives::U256: TryFrom<<Runtime as Config<Instance>>::Balance>,
{
	type T = Runtime;
	type Interface = IERC20::IERC20Calls;
	const MATCHER: AddressMatcher = PrecompileConfig::MATCHER;
	const HAS_CONTRACT_INFO: bool = false;
```

**File:** substrate/frame/assets/precompiles/src/lib.rs (L261-294)
```rust
	/// Execute the transfer call.
	fn transfer(
		asset_id: <Runtime as Config<Instance>>::AssetId,
		call: &IERC20::transferCall,
		env: &mut impl Ext<T = Runtime>,
	) -> Result<Vec<u8>, Error> {
		env.charge(<Runtime as Config<Instance>>::WeightInfo::transfer())?;

		let from = Self::caller(env)?;
		let dest = <Runtime as pallet_revive::Config>::AddressMapper::to_account_id(
			&call.to.into_array().into(),
		);

		let f = TransferFlags { keep_alive: false, best_effort: false, burn_dust: false };
		pallet_assets::Pallet::<Runtime, Instance>::do_transfer(
			asset_id,
			&<Runtime as pallet_revive::Config>::AddressMapper::to_account_id(&from),
			&dest,
			Self::to_balance(call.value)?,
			None,
			f,
		)?;

		Self::deposit_event(
			env,
			IERC20Events::Transfer(IERC20::Transfer {
				from: from.0.into(),
				to: call.to,
				value: call.value,
			}),
		)?;

		Ok(IERC20::transferCall::abi_encode_returns(&true))
	}
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs (L1398-1410)
```rust
	type Precompiles = (
		ERC20<Self, InlineIdConfig<{ TRUST_BACKED_ASSETS_PRECOMPILE }>, TrustBackedAssetsInstance>,
		ERC20<Self, InlineIdConfig<{ POOL_ASSETS_PRECOMPILE }>, PoolAssetsInstance>,
		ERC20<
			Self,
			ForeignIdConfig<{ FOREIGN_ASSETS_PRECOMPILE }, Self, ForeignAssetsInstance>,
			ForeignAssetsInstance,
		>,
		XcmPrecompile<Self>,
		pallet_asset_conversion_precompiles::AssetConversion<{ ASSET_CONVERSION_PRECOMPILE }, Self>,
		VestingPrecompile<Self>,
	);
	type AddressMapper = pallet_revive::AccountId32Mapper<Self>;
```
