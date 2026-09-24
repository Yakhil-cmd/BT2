This is a real analog. The `ERC20Transactor` (added specifically to let XCM programs interact with arbitrary `pallet-revive` smart-contract "assets") exhibits exactly the fee-on-transfer accounting bug described in the report: it credits the XCM holding register with the *requested* amount based only on the ERC20 call returning `true`, never verifying how much value the checking account actually received.

### Title
ERC20Transactor credits XCM holding with the requested amount instead of the actually-transferred amount, breaking backing invariants for fee-on-transfer/deflationary ERC20 "assets" - (File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs)

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, used by the XCM executor whenever an XCM `Asset` location matches an `AccountKey20` (i.e. any `pallet-revive` contract address), move value by calling the target contract's Solidity `transfer(address,uint256)` function and then unconditionally construct `Erc20Credit(amount)` / treat the operation as fully successful as soon as the contract's boolean return decodes to `true` — with no verification of the checking account's (or beneficiary's) actual balance delta. [1](#0-0) 

### Finding Description
The `TransactAsset` trait explicitly documents that `withdraw_asset` must "Return the actual asset(s) withdrawn, which should always be equal to `_what`": [2](#0-1) 

`ERC20Transactor` violates this by trusting the callee contract's self-reported boolean success rather than measuring actual balance movement — the identical root cause as the reported Unitas `_swapIn()` bug, where `_setBalance()` used the requested `amount` instead of the delta actually received via `safeTransferFrom`.

In `withdraw_asset_with_surplus`, the transactor calls `IERC20::transfer(checking_account, amount)` on the arbitrary contract at `asset_id` (any AccountKey20 location, matched by `ERC20Matcher`/`IsLocalAccountKey20`), and on `is_success == true` it manufactures `Erc20Credit(amount)` into the XCM `AssetsInHolding` register: [3](#0-2) [4](#0-3) 

An ERC20 contract is fully attacker-controlled code (any signed account can deploy one via `pallet-revive`'s permissionless `InstantiateOrigin: EnsureSigned<Self::AccountId>` in the Asset Hub Westend runtime), so an attacker can trivially implement `transfer()` to:
- always `return true`,
- but move less than `value` to `to` (a fee-on-transfer/deflationary token), or move `0`.

Because `ERC20Matcher` matches *every* local `AccountKey20` location (not an allow-list of vetted contracts) via `IsLocalAccountKey20`, this transactor is invoked for such a contract inside any XCM program the attacker submits (e.g. via the permissionless `pallet_xcm::execute` extrinsic).

The symmetric bug exists in `deposit_asset_with_surplus`: it transfers `amount` out of the checking account and, as long as the call returns `true` (again attacker-controlled), treats the deposit as fully successful and drops the entire `AssetsInHolding` credit without checking the beneficiary actually received `amount`: [5](#0-4) 

This desynchronizes the XCM executor's internal ledger (the value it believes is now "in holding" / "backed" by the checking account) from what the checking account contract actually holds. Since this transactor is composed into the runtime's `AssetTransactors` tuple used for all XCM asset handling (including any reserve/teleport wiring that treats the checking account as the collateral backing a cross-chain representation), any downstream logic that assumes 1:1 backing between the checking account's real ERC20 balance and the nominal amount recorded in XCM `AssetsInHolding`/reserve accounting is violated — precisely the invariant break flagged in the original report. [6](#0-5) 

### Impact Explanation
This is an internal-accounting/backing-integrity violation, not a direct fund-theft-from-others primitive by itself: the ERC20 token is attacker-deployed and the desynchronized checking-account balance vs. recorded holding amount only manifests as an inconsistency for that specific ERC20 asset. It matches Medium severity because:
- It breaks a documented safety invariant (`withdraw_asset` returning exactly `_what`) relied upon by the wider XCM executor and any composed reserve-based cross-chain flows for this asset class.
- If the checking account is later treated as reserve backing for a wrapped/foreign representation of the ERC20 on another chain (via reserve-transfer instructions routed through this transactor), the mismatch between recorded nominal value and real locked value creates unbacked issuance risk downstream, and/or causes later legitimate withdrawals for the same contract to unexpectedly fail (best case) due to insufficient real balance versus assumed balance (denial of service for other users of the same ERC20 asset id, if it is a shared, non-attacker-controlled contract used by unrelated victims).

### Likelihood Explanation
Likelihood is limited by two factors that keep it Medium rather than Critical/High:
- The attacker must control the ERC20 contract's code themselves for the mismatch to be attacker-favorable (they cannot force a third-party fee-on-transfer token's behavior).
- Exploiting this into cross-chain unbacked issuance additionally depends on runtime-specific reserve/teleport trust configuration explicitly whitelisting this checking account/asset as a trusted reserve for a foreign asset elsewhere, which was not confirmed to be configured for the generic ERC20 case in the inspected runtime.

That said, the *local* accounting-mismatch (checking account under/over-funded relative to recorded `AssetsInHolding`) is trivially and deterministically reproducible today by any signed account via `pallet_xcm::execute` with a `WithdrawAsset` referencing a self-deployed fee-on-transfer contract at an `AccountKey20` location — no privileged role or governance action required.

### Recommendation
In `ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` (`cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs`), measure the actual balance delta of the checking account/beneficiary before and after the `transfer()` call (via `IERC20::balanceOf`) instead of trusting the boolean return value, and construct `Erc20Credit`/treat the operation as successful using that measured delta — mirroring the report's recommended fix of comparing `balanceBefore`/`balanceAfter` rather than assuming the nominal `amount` was moved.

### Proof of Concept
Deployment evidence (code-level, not executed): the vulnerable code path is reachable without any special privilege — `pallet_revive::Config::InstantiateOrigin = EnsureSigned<Self::AccountId>` on Asset Hub Westend allows any signed account to deploy a malicious ERC20 contract, and `ERC20Matcher = MatchedConvertedConcreteId<H160, u128, IsLocalAccountKey20, ...>` matches its address as a valid XCM `Asset` location automatically: [7](#0-6) [8](#0-7) 

No test was executed in this environment (no filesystem/terminal access here); this analysis is based on static code inspection of the cited files. A minimal integration reproduction would: (1) deploy a `pallet-revive` contract whose `transfer()` always returns `true` but forwards only 50% of `value`; (2) call `pallet_xcm::execute` with `WithdrawAsset` for that contract's `AccountKey20` location for amount `A`; (3) assert the executor's `AssetsInHolding` reports `A` while `IERC20::balanceOf(checking_account)` only increased by `A/2` — demonstrating the accounting break at `erc20_transactor.rs:198-201`.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L159-208)
```rust
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
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L251-280)
```rust
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
```

**File:** polkadot/xcm/xcm-executor/src/traits/transact_asset.rs (L102-117)
```rust
	/// Withdraw the given asset from the consensus system.
	///
	/// Return the actual asset(s) withdrawn, which should always be equal to `_what`.
	///
	/// The XCM `_maybe_context` parameter may be `None` when the caller of `withdraw_asset` is
	/// outside of the context of a currently-executing XCM. An example will be the `charge_fees`
	/// method in the XCM executor.
	///
	/// Implementations should return `XcmError::FailedToTransactAsset` if withdraw failed.
	fn withdraw_asset(
		_what: &Asset,
		_who: &Location,
		_maybe_context: Option<&XcmContext>,
	) -> Result<AssetsInHolding, XcmError> {
		Err(XcmError::Unimplemented)
	}
```

**File:** cumulus/parachains/runtimes/assets/common/src/lib.rs (L132-161)
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

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs (L239-246)
```rust
/// Means for transacting assets on this chain.
pub type AssetTransactors = (
	FungibleTransactor,
	FungiblesTransactor,
	ForeignFungiblesTransactor,
	UniquesTransactor,
	ERC20Transactor,
);
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs (L1387-1415)
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
```
