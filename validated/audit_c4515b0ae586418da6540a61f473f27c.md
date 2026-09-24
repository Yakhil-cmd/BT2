### Title
ERC20Transactor trusts fraudulent ERC20 `transfer()` return value instead of verifying actual token balance movement, allowing unbacked asset credit through XCM - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `::deposit_asset_with_surplus` implement the `TransactAsset` XCM trait for ERC20-style tokens deployed via `pallet-revive`. Both functions move "value" purely by calling the Solidity `transfer()` selector and trusting the ABI-decoded boolean return value as proof that tokens actually moved, exactly the anti-pattern described in the referenced Ajna `ERC20Pool` report. Since `ERC20Matcher` (`cumulus/parachains/runtimes/assets/common/src/lib.rs:159-160`) matches *any* local `AccountKey20` location as a valid fungible asset id, any user can deploy an arbitrary contract via `pallet-revive` that pretends to be an ERC20 (returns `true` without actually moving a balance) and have the XCM executor mint an `AssetsInHolding` credit for an arbitrary attacker-chosen `amount`.

### Finding Description
`withdraw_asset_with_surplus` ( [1](#0-0) ) calls `IERC20::transferCall` via `pallet_revive::Pallet::<T>::bare_call` from the *withdrawing account* to the `TransfersCheckingAccount`, then, if the call doesn't revert and ABI-decodes to `true`, immediately mints a fungible credit of the attacker-controlled `amount` into `AssetsInHolding` via `Erc20Credit(amount)` [2](#0-1) . There is no check of the checking account's ERC20 balance before and after the call — the code only checks `did_revert()` and the decoded boolean. Symmetrically, `deposit_asset_with_surplus` trusts the same boolean when "returning" the checking account's tokens to a beneficiary [3](#0-2) .

The asset id and amount that reach this code come from `ERC20Matcher = MatchedConvertedConcreteId<H160, u128, IsLocalAccountKey20, AccountKey20ToH160, TryConvertInto>` ( [4](#0-3) ), which matches *any* local `AccountKey20` (i.e., any contract address deployed under `pallet-revive`), not a registered/whitelisted list of legitimate ERC20 contracts. `IsLocalAccountKey20` only checks the shape of the `Location`, not the contract's identity or provenance.

The transactor is wired into a live-shaped runtime configuration, `AssetTransactors` on Asset Hub Westend: `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs:213-246` includes `ERC20Transactor` in the tuple of `AssetTransactors` used by the XCM executor for that chain ( [5](#0-4) ).

Reachability requires no privilege: `pallet_xcm::Pallet::execute` is a signed-origin extrinsic (`ExtrinsicOrigin -> ExecuteXcmOrigin`) that lets any signed account submit an arbitrary XCM program that is run through the exact same `XcmExecutor`/`AssetTransactors` stack [6](#0-5) , [7](#0-6) . An attacker can:
1. Deploy a malicious ERC20-like contract via `pallet-revive` whose `transfer()` always returns `true` (or specifically for the `TransfersCheckingAccount` target) without moving any internal balance/allowance state.
2. Submit an `execute` XCM program: `WithdrawAsset(AccountKey20(malicious_contract), amount)` where `amount` is entirely attacker-chosen.
3. `ERC20Transactor::withdraw_asset_with_surplus` invokes `transferCall` to the checking account, gets `true` back (lie), and mints `amount` worth of `Erc20Credit` into the XCM holding register — completely unbacked by any real balance change in the malicious contract or the checking account.
4. That unbacked holding can then be consumed by any subsequent instruction that treats the holding as legitimate value — e.g. `DepositAsset` to another account, `ExchangeAsset` against a real liquidity pool created via `pallet_asset_conversion` (also present in the same crate as `PoolAdapter`, `cumulus/parachains/runtimes/assets/common/src/lib.rs:177-242`), letting the attacker redeem the fabricated credit for a real backing asset if a pool pairing the fake ERC20 with a real asset exists.

This is the precise Polkadot/XCM analog of the reported bug class: an asset-transfer routine trusts a callee-controlled boolean success signal instead of verifying that a real balance changed, and the "ERC20" in question is fully attacker-controlled (any deployed contract, no allowlist), just as the Ajna pool trusted any user-supplied ERC20 token contract.

### Impact Explanation
If any XCM instruction downstream of `WithdrawAsset` (e.g. `ExchangeAsset` via `pallet_asset_conversion`, or forwarding/backing a message to another chain that treats the asset as genuinely reserved) treats the resulting `AssetsInHolding` credit as real value, an attacker can mint unbacked "value" for an arbitrary amount and redeem/move it — a direct integrity break (unbacked issuance) analogous to draining real collateral in the referenced Ajna report. This would be High severity if a live path exists that converts this credit into real backed assets (e.g., liquidity pool drain); the credit alone, confined to the fabricated token's own accounting, has no intrinsic value.

### Likelihood Explanation
Likelihood is High for triggering the flawed trust logic itself (deploying a contract with a lying `transfer()` and calling `pallet_xcm::execute` are both unprivileged, ordinary user actions), but the *downstream monetizable* impact (redeeming the fabricated credit for real value, e.g. via an asset-conversion pool) requires additional configuration/state (an existing pool pairing the fake ERC20 asset id with a real backed asset, or some other component that accepts this fungible id as legitimate collateral). I was not able to verify, within the available tooling, whether `pallet_asset_conversion` pool creation genuinely permits pairing an `AccountKey20`-matched pseudo-asset with a real trust-backed/foreign asset on a runtime where `ERC20Transactor` is also configured, nor whether `ERC20Transactor` is included in the equivalent Asset Hub Polkadot (mainnet) runtime configuration — only `asset-hub-westend` was found to reference `ERC20Transactor` in the indexed code.

### Recommendation
In `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, read the ERC20 contract's `balanceOf` for the relevant account before and after the `transferCall` (or otherwise use `pallet-revive`'s underlying storage/state inspection) and require that the balance delta equals the requested `amount`, instead of trusting the ABI-decoded boolean return value alone. This mirrors the standard "measure actual balance change" mitigation recommended in the referenced report. Additionally, consider whether `ERC20Matcher`/`IsLocalAccountKey20` should restrict to an allowlisted/registered set of ERC20 contracts rather than matching any deployed contract address.

### Proof of Concept
A full concrete PoC was not executed against a live runtime or test harness within this investigation; the analysis is based on static code tracing through the referenced files. Executing this would require: (1) a local Substrate test harness including `pallet-revive`, `pallet-xcm`, `ERC20Transactor`, and `ERC20Matcher` wired together (as in `asset-hub-westend`), (2) deploying a malicious Solidity/PVM contract whose `transfer()` unconditionally returns `true`, (3) calling `PolkadotXcm::execute` with a `WithdrawAsset` targeting that contract's address as an `AccountKey20` asset id, and (4) asserting that `AssetsInHolding` contains the requested `amount` despite the checking account's real (mocked) ERC20 balance being unchanged. This reproduction was not run; test execution status: **not attempted/no results** due to tool constraints (read-only code search only, no code execution capability available in this session).

### Citations

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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L270-298)
```rust
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
```

**File:** cumulus/parachains/runtimes/assets/common/src/lib.rs (L132-160)
```rust
/// `Contains<Location>` implementation that matches locations with no parents,
/// a `PalletInstance` and an `AccountKey20` junction.
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

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs (L221-246)
```rust
/// Transactor for ERC20 tokens.
pub type ERC20Transactor = assets_common::ERC20Transactor<
	// We need this for accessing pallet-revive.
	Runtime,
	// The matcher for smart contracts.
	assets_common::ERC20Matcher,
	// How to convert from a location to an account id.
	LocationToAccountId,
	// The maximum gas that can be used by a standard ERC20 transfer.
	ERC20TransferGasLimit,
	// The maximum storage deposit that can be used by a standard ERC20 transfer.
	ERC20TransferStorageDepositLimit,
	// We're generic over this so we can't escape specifying it.
	AccountId,
	// Checking account for ERC20 transfers.
	ERC20TransfersCheckingAccount,
>;

/// Means for transacting assets on this chain.
pub type AssetTransactors = (
	FungibleTransactor,
	FungiblesTransactor,
	ForeignFungiblesTransactor,
	UniquesTransactor,
	ERC20Transactor,
);
```

**File:** polkadot/xcm/pallet-xcm/src/lib.rs (L370-397)
```rust
	impl<T: Config> ExecuteController<OriginFor<T>, <T as Config>::RuntimeCall> for Pallet<T> {
		type WeightInfo = Self;
		fn execute(
			origin: OriginFor<T>,
			message: Box<VersionedXcm<<T as Config>::RuntimeCall>>,
			max_weight: Weight,
		) -> Result<Weight, DispatchErrorWithPostInfo> {
			tracing::trace!(target: "xcm::pallet_xcm::execute", ?message, ?max_weight);
			let outcome = (|| {
				let origin_location = T::ExecuteXcmOrigin::ensure_origin(origin)?;
				let mut hash = message.using_encoded(sp_io::hashing::blake2_256);
				let message = (*message).try_into().map_err(|()| {
					tracing::debug!(
						target: "xcm::pallet_xcm::execute", id=?hash,
						"Failed to convert VersionedXcm to Xcm",
					);
					Error::<T>::BadVersion
				})?;
				let value = (origin_location, message);
				ensure!(T::XcmExecuteFilter::contains(&value), Error::<T>::Filtered);
				let (origin_location, message) = value;
				Ok(T::XcmExecutor::prepare_and_execute(
					origin_location,
					message,
					&mut hash,
					max_weight,
					max_weight,
				))
```

**File:** polkadot/xcm/pallet-xcm/src/lib.rs (L1235-1245)
```rust
		#[pallet::call_index(3)]
		#[pallet::weight(max_weight.saturating_add(T::WeightInfo::execute()))]
		pub fn execute(
			origin: OriginFor<T>,
			message: Box<VersionedXcm<<T as Config>::RuntimeCall>>,
			max_weight: Weight,
		) -> DispatchResultWithPostInfo {
			let weight_used =
				<Self as ExecuteController<_, _>>::execute(origin, message, max_weight)?;
			Ok(Some(weight_used.saturating_add(T::WeightInfo::execute())).into())
		}
```
