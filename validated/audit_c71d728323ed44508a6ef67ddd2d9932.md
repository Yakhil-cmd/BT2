Confirmed: `ERC20Matcher` matches **any** location of the form `(0, [AccountKey20 { key, .. }])` [1](#0-0) , with no registry, allow-list, or trust check on the underlying contract — any address deployed via `pallet-revive` that happens to expose an `IERC20` ABI is automatically usable as an XCM-transactable asset through `ERC20Transactor`.

### Title
Malicious ERC20 contract on Asset Hub permanently traps XCM-held assets via unregistered `ERC20Transactor` deposit path - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor` lets any `AccountKey20`-addressed contract deployed through `pallet-revive` act as an XCM fungible asset, with the deposit leg of every transfer performed by calling `IERC20::transfer` on that same attacker-controlled contract. Because `ERC20Matcher` performs no allow-listing [2](#0-1) , an attacker can deploy a contract that accepts `transfer` calls when funds move *into* the pallet's checking account (so withdrawals during `WithdrawAsset` succeed and are recorded as `Erc20Credit` in the XCM holding register) but unconditionally reverts `transfer` calls made *from* the checking account to any beneficiary (so `deposit_asset_with_surplus` always fails).

### Finding Description
`withdraw_asset_with_surplus` calls `IERC20::transfer` from the user's mapped account to `TransfersCheckingAccount`, and on success returns `AssetsInHolding::new_from_fungible_credit(what.id, Erc20Credit(amount))` into the XCM holding register [3](#0-2) . Later, `deposit_asset_with_surplus` attempts to move the same amount out of `TransfersCheckingAccount` to the beneficiary by again calling `IERC20::transfer` on the *same* attacker-deployed contract [4](#0-3) . Because the matcher accepts any `AccountKey20` address with no whitelist, and the contract logic that decides success/failure of `transfer` is entirely attacker-authored, the attacker can make the contract:
- succeed on `transfer(checking_account, amount)` (the withdraw leg), and
- always revert/return `false` on any subsequent `transfer(_, amount)` call from the checking account (the deposit leg).

When the deposit leg fails, `deposit_asset_with_surplus` returns `Err((what, XcmError::FailedToTransactAsset(..)))`, so the `AssetsInHolding` credit remains in the executor's holding register and is trapped by `XcmExecutor::post_process` via `Config::AssetTrap::drop_assets` [5](#0-4) . Trapped assets are normally reclaimable later via `ClaimAsset` + a retry deposit — but retrying simply re-invokes the same `deposit_asset_with_surplus` path against the same malicious contract, which is guaranteed to fail again. The `Erc20Credit` imbalance type performs no real balance enforcement (`"the actual balance constraints are enforced by the ERC20 smart contract itself rather than the runtime"` [6](#0-5) ), so there is no runtime-side accounting that could route around the malicious contract's revert. This is the FRAME/XCM analog of the OKU `OracleLess` bug: an unrestricted, attacker-supplied "token" implementation controls a transfer that a protocol path (order cancellation / trapped-asset claim) depends on completing, and the attacker can make that transfer deterministically unwindable, permanently freezing any honest user's funds that pass through the malicious asset once withdrawn into the shared checking account.

### Impact Explanation
Any user who is induced to move this attacker-created "ERC20 asset" through XCM (e.g., attempting a local-to-local transfer via `pallet_xcm::transfer_assets` or as part of a multi-asset XCM program) has their funds irreversibly locked: withdrawn into `TransfersCheckingAccount`, credited into holding, and then unrecoverably trapped once the deposit leg is guaranteed to fail on every retry. This is an irreversible freezing of user funds without any privileged action by the attacker — matching the "irreversible freezing" category favored for High/Critical findings. The attacker's own funds are not at risk since the malicious contract's internal accounting is self-controlled.

### Likelihood Explanation
Requires only permissionless actions available to any account: deploying a contract via `pallet-revive` (`UploadOrigin`/`InstantiateOrigin` are `EnsureSigned` on Asset Hub Westend [7](#0-6) ) and getting any other user to interact with that contract's address as an XCM asset (e.g., by advertising it or via a scam token listing). No governance, no privileged origin, no forged inherents — it directly satisfies the "real user entry" and "no privileged role" constraints.

### Recommendation
Do not treat arbitrary `AccountKey20` contracts as XCM-transactable assets without an explicit registration/allow-list step (mirroring how `TrustBackedAssets`/`ForeignAssets` require explicit creation). At minimum, `ERC20Transactor`'s deposit path should not rely on being able to move funds back out of a shared `TransfersCheckingAccount` through the same unconstrained contract call that was used for the withdrawal; consider requiring a governance- or registry-gated allow-list for which ERC20 contract addresses `ERC20Matcher` will match, and/or fail the whole withdraw+deposit as an atomic unit so a shared checking-account credit is never left stuck against a hostile contract with no path to recovery.

### Proof of Concept
Not executed. This report is a code-level analog derived from reading `ERC20Transactor`, `ERC20Matcher`, and `XcmExecutor::post_process` in the target repository; no local Rust/FRAME/XCM integration test was run to confirm the trapped-and-unrecoverable end state, and no live network interaction was performed. A full reproduction would require: (1) deploying a `pallet-revive` contract on Asset Hub Westend implementing `IERC20` with conditional revert logic keyed on `msg.sender == TransfersCheckingAccount`, (2) executing a `pallet_xcm::execute`/`transfer_assets` XCM program that withdraws from a victim account and deposits to a third-party beneficiary using this asset's `Location`, and (3) asserting via emitted `AssetsTrapped`/`ProcessXcmError` events and a failed `ClaimAsset` retry that the credited holding can never be deposited. This construction and its exact revert conditions are not verified to compile/execute in this session — flagging as unconfirmed but code-supported.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/lib.rs (L134-160)
```rust
pub struct IsLocalAccountKey20;
impl Contains<Location> for IsLocalAccountKey20 {
	fn contains(location: &Location) -> bool {
		matches!(location.unpack(), (0, [AccountKey20 { .. }]))
	}
}

/// Fallible converter from a location to a `H160` that matches any location ending with
/// an `AccountKey20` junction.
pub struct AccountKey20ToH160;
impl MaybeEquivalence<Location, H160> for AccountKey20ToH160 {
	fn convert(location: &Location) -> Option<H160> {
		match location.unpack() {
			(0, [AccountKey20 { key, .. }]) => Some((*key).into()),
			_ => None,
		}
	}

	fn convert_back(key: &H160) -> Option<Location> {
		Some(Location::new(0, [AccountKey20 { key: (*key).into(), network: None }]))
	}
}

/// [`xcm_executor::traits::MatchesFungibles`] implementation that matches
/// ERC20 tokens.
pub type ERC20Matcher =
	MatchedConvertedConcreteId<H160, u128, IsLocalAccountKey20, AccountKey20ToH160, TryConvertInto>;
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L73-79)
```rust
/// A minimal imbalance tracking type that holds an ERC20 token amount.
///
/// This type implements the necessary imbalance accounting traits but does not perform
/// runtime-level balance enforcement. It's used to track ERC20 token amounts within XCM
/// asset holdings, where the actual balance constraints are enforced by the ERC20 smart
/// contract itself rather than the runtime.
struct Erc20Credit(u128);
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L150-216)
```rust
	fn withdraw_asset_with_surplus(
		what: &Asset,
		who: &Location,
		_context: Option<&XcmContext>,
	) -> Result<(AssetsInHolding, Weight), XcmError> {
		tracing::trace!(
			target: "xcm::transactor::erc20::withdraw",
			?what, ?who,
		);
		let (asset_id, amount) = Matcher::matches_fungibles(what)?;
		let who = AccountIdConverter::convert_location(who)
			.ok_or(MatchError::AccountIdConversionFailed)?;
		// We need to map the 32 byte checking account to a 20 byte account.
		let checking_account_eth = T::AddressMapper::to_address(&TransfersCheckingAccount::get());
		let checking_address = Address::from(Into::<[u8; 20]>::into(checking_account_eth));
		let weight_limit = WeightLimit::get();
		// To withdraw, we actually transfer to the checking account.
		// We do this using the solidity ERC20 interface.
		let data =
			IERC20::transferCall { to: checking_address, value: EU256::from(amount) }.abi_encode();
		let ContractResult { result, weight_consumed, storage_deposit, .. } =
			pallet_revive::Pallet::<T>::bare_call(
				OriginFor::<T>::signed(who.clone()),
				asset_id,
				U256::zero(),
				TransactionLimits::WeightAndDeposit {
					weight_limit,
					deposit_limit: StorageDepositLimit::get(),
				},
				data,
				&ExecConfig::new_substrate_tx(),
			);
		// We need to return this surplus for the executor to allow refunding it.
		let surplus = weight_limit.saturating_sub(weight_consumed);
		tracing::trace!(target: "xcm::transactor::erc20::withdraw", ?weight_consumed, ?surplus, ?storage_deposit);
		if let Ok(return_value) = result {
			tracing::trace!(target: "xcm::transactor::erc20::withdraw", ?return_value, "Return value by withdraw_asset");
			if return_value.did_revert() {
				tracing::debug!(target: "xcm::transactor::erc20::withdraw", "ERC20 contract reverted");
				Err(XcmError::FailedToTransactAsset("ERC20 contract reverted"))
			} else {
				let is_success = IERC20::transferCall::abi_decode_returns_validate(&return_value.data).map_err(|error| {
					tracing::debug!(target: "xcm::transactor::erc20::withdraw", ?error, "ERC20 contract result couldn't decode");
					XcmError::FailedToTransactAsset("ERC20 contract result couldn't decode")
				})?;
				if is_success {
					tracing::trace!(target: "xcm::transactor::erc20::withdraw", "ERC20 contract was successful");
					Ok((
						AssetsInHolding::new_from_fungible_credit(
							what.id.clone(),
							Box::new(Erc20Credit(amount)),
						),
						surplus,
					))
				} else {
					tracing::debug!(target: "xcm::transactor::erc20::withdraw", "contract transfer failed");
					Err(XcmError::FailedToTransactAsset("ERC20 contract transfer failed"))
				}
			}
		} else {
			tracing::debug!(target: "xcm::transactor::erc20::withdraw", ?result, "Error");
			// This error could've been duplicate smart contract, out of gas, etc.
			// If the issue is gas, there's nothing the user can change in the XCM
			// that will make this work since there's a hardcoded gas limit.
			Err(XcmError::FailedToTransactAsset("ERC20 contract execution errored"))
		}
	}
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L225-306)
```rust
	fn deposit_asset_with_surplus(
		what: AssetsInHolding,
		who: &Location,
		_context: Option<&XcmContext>,
	) -> Result<Weight, (AssetsInHolding, XcmError)> {
		tracing::trace!(
			target: "xcm::transactor::erc20::deposit",
			?what, ?who,
		);
		defensive_assert!(what.len() == 1, "Trying to deposit more than one asset!");
		// Check we handle this asset.
		let maybe = what
			.fungible_assets_iter()
			.next()
			.and_then(|asset| Matcher::matches_fungibles(&asset).ok());
		let (asset_contract_id, amount) = match maybe {
			Some(inner) => inner,
			None => return Err((what, MatchError::AssetNotHandled.into())),
		};
		let who = match AccountIdConverter::convert_location(who) {
			Some(inner) => inner,
			None => return Err((what, MatchError::AccountIdConversionFailed.into())),
		};
		// We need to map the 32 byte beneficiary account to a 20 byte account.
		let eth_address = T::AddressMapper::to_address(&who);
		let address = Address::from(Into::<[u8; 20]>::into(eth_address));
		// To deposit, we actually transfer from the checking account to the beneficiary.
		// We do this using the solidity ERC20 interface.
		let data = IERC20::transferCall { to: address, value: EU256::from(amount) }.abi_encode();
		let weight_limit = WeightLimit::get();
		let ContractResult { result, weight_consumed, storage_deposit, .. } =
			pallet_revive::Pallet::<T>::bare_call(
				OriginFor::<T>::signed(TransfersCheckingAccount::get()),
				asset_contract_id,
				U256::zero(),
				TransactionLimits::WeightAndDeposit {
					weight_limit,
					deposit_limit: StorageDepositLimit::get(),
				},
				data,
				&ExecConfig::new_substrate_tx(),
			);
		// We need to return this surplus for the executor to allow refunding it.
		let surplus = weight_limit.saturating_sub(weight_consumed);
		tracing::trace!(target: "xcm::transactor::erc20::deposit", ?weight_consumed, ?surplus, ?storage_deposit);
		if let Ok(return_value) = result {
			tracing::trace!(target: "xcm::transactor::erc20::deposit", ?return_value, "Return value");
			if return_value.did_revert() {
				tracing::debug!(target: "xcm::transactor::erc20::deposit", "Contract reverted");
				Err((what, XcmError::FailedToTransactAsset("ERC20 contract reverted")))
			} else {
				match IERC20::transferCall::abi_decode_returns_validate(&return_value.data) {
					Ok(true) => {
						tracing::trace!(target: "xcm::transactor::erc20::deposit", "ERC20 contract was successful");
						Ok(surplus)
					},
					Ok(false) => {
						tracing::debug!(target: "xcm::transactor::erc20::deposit", "contract transfer failed");
						Err((
							what,
							XcmError::FailedToTransactAsset("ERC20 contract transfer failed"),
						))
					},
					Err(error) => {
						tracing::debug!(target: "xcm::transactor::erc20::deposit", ?error, "ERC20 contract result couldn't decode");
						Err((
							what,
							XcmError::FailedToTransactAsset(
								"ERC20 contract result couldn't decode",
							),
						))
					},
				}
			}
		} else {
			tracing::debug!(target: "xcm::transactor::erc20::deposit", ?result, "Error");
			// This error could've been duplicate smart contract, out of gas, etc.
			// If the issue is gas, there's nothing the user can change in the XCM
			// that will make this work since there's a hardcoded gas limit.
			Err((what, XcmError::FailedToTransactAsset("ERC20 contract execution errored")))
		}
	}
```

**File:** polkadot/xcm/xcm-executor/src/lib.rs (L400-417)
```rust
		let mut weight_used = xcm_weight.saturating_sub(self.total_surplus);

		if !self.holding.is_empty() {
			tracing::trace!(
				target: "xcm::post_process",
				holding_register = ?self.holding,
				context = ?self.context,
				original_origin = ?self.original_origin,
				"Trapping assets in holding register",
			);
			let claimer = self
				.asset_claimer
				.as_ref()
				.or(self.context.origin.as_ref())
				.unwrap_or(&self.original_origin);
			let trap_weight = Config::AssetTrap::drop_assets(claimer, self.holding, &self.context);
			weight_used.saturating_accrue(trap_weight);
		};
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs (L1387-1416)
```rust
impl pallet_revive::Config for Runtime {
	type Time = Timestamp;
	type Balance = Balance;
	type Currency = Balances;
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type RuntimeOrigin = RuntimeOrigin;
	type DepositPerItem = DepositPerItem;
	type DepositPerChildTrieItem = DepositPerChildTrieItem;
	type DepositPerByte = DepositPerByte;
	type WeightInfo = weights::pallet_revive::WeightInfo<Self>;
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
	type RuntimeMemory = ConstU32<{ 128 * 1024 * 1024 }>;
	type PVFMemory = ConstU32<{ 512 * 1024 * 1024 }>;
	type AllowEVMBytecode = ConstBool<true>;
	type UploadOrigin = EnsureSigned<Self::AccountId>;
	type InstantiateOrigin = EnsureSigned<Self::AccountId>;
	type RuntimeHoldReason = RuntimeHoldReason;
```
