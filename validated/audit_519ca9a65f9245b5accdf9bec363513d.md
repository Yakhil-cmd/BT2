### Title
ERC20Transactor blindly trusts return value of any attacker-deployed contract to determine asset withdrawal/deposit success and credited amount - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
The Maple report's root cause was that `fundLoan()` derived `treasuryFee`, `investorFee`, `mapleTreasury` and `poolDelegate` from an attacker-supplied `lender_` contract via `ILenderLike`, and blindly trusted those self-reported values to decide how much value moved and to whom. The Polkadot SDK analog is `ERC20Transactor::withdraw_asset_with_surplus` / `deposit_asset_with_surplus`, which trusts the boolean return value of a `transfer()` call on an arbitrary, attacker-controlled `pallet-revive` contract to decide whether an XCM asset withdrawal/deposit "succeeded" and how much value to credit into `AssetsInHolding` — with no independent verification (e.g. balance-delta check) of whether any real value actually moved.

### Finding Description
`ERC20Matcher` is defined as: [1](#0-0) 

`IsLocalAccountKey20::contains` matches **any** location of the shape `(0, [AccountKey20 { .. }])` — there is no allowlist, registry, or issuance check tying the `key` (an EVM address) to a chain-approved token contract. Any account/location whose interior is `AccountKey20{ key }` is accepted as a valid "ERC20 asset id" by the matcher, and `key` is fully attacker-chosen (it can be the address of any contract the attacker deploys via `pallet-revive`, which is a real, permitted user entry point on Asset Hub Westend).

`ERC20Transactor` is wired into the runtime's `AssetTransactors` tuple: [2](#0-1) 

In `withdraw_asset_with_surplus`, the transactor calls `bare_call` on the contract at `asset_id` (the attacker-controlled `key`) with an ERC20 `transfer` payload, and then trusts the ABI-decoded boolean return value as proof that `amount` tokens moved: [3](#0-2) 

The same pattern occurs in `deposit_asset_with_surplus`, which calls `transfer()` from the checking account to the beneficiary and again trusts only the decoded boolean: [4](#0-3) 

At no point does the transactor read `balanceOf` before/after the call, verify an emitted `Transfer` event, or otherwise check that state actually changed by `amount`. It only checks: (a) the call didn't revert, and (b) the contract's own self-reported return value decodes to `true`. Since `asset_id`/`key` is the address of a contract the attacker fully controls and deploys themselves (no privileged role required — `pallet-revive` contract instantiation is a standard permitted extrinsic), the attacker can write a trivial contract whose `transfer()` always returns `true` (ABI-encoded `0x...01`) without moving any balance, or moves an arbitrary amount unconnected to actual reserves. This mirrors Maple's flaw exactly: fee/value-transfer success and amount are derived from data self-reported by an entity the attacker controls (`ILenderLike` there, an arbitrary ERC20-shaped contract here), rather than from an authoritative, independently-verified source.

The consequence is that `AssetsInHolding` — the XCM executor's in-flight ledger of "real" value for the duration of one XCM program — can be credited with `Erc20Credit(amount)` units that have no actual backing, purely because the attacker's own contract lied about a `transfer()` outcome.

### Impact Explanation
Within `pallet_xcm::execute`/`send` (a normal, permissionless, signed-origin extrinsic), any user can reference an `Asset` with `id: (0, [AccountKey20{ key: <their own deployed contract> }])` in `WithdrawAsset`/`TransferAsset`/`DepositAsset` instructions. Because `ERC20Matcher` accepts any such location unconditionally, and `ERC20Transactor` trusts the contract's self-reported success, the attacker can make the XCM executor believe an arbitrary amount of "ERC20 value" was validly withdrawn/deposited without any real balance backing it. Any downstream instruction within the same (or a related) XCM program that treats holding-register balances as real (e.g., further transfers, fee payment via a generic weight trader, or an asset-conversion pool interaction involving this asset id) would then be operating on fabricated value — an unbacked-issuance-style primitive analogous to Maple's fabricated fee/treasury values.

I was not able, within the available investigation budget, to fully trace whether Asset Hub Westend's configured `WeightTrader`/`AssetExchanger` (e.g. a generic trader that accepts any `AssetTransactor`-withdrawable asset for `BuyExecution`, or an `asset-conversion` pool paired with this ERC20 asset id) is reachable and would let the attacker convert this fabricated credit into real DOT/USDT taken from other users. That final link — necessary to escalate this from "unbacked in-flight credit" to concrete theft of counterparties' funds — remains unverified due to the iteration limit, and should be checked explicitly (`TakeFirstAssetTrader`/weight-trading config and `pallet-asset-conversion` pool-creation permissions for arbitrary AccountKey20 asset ids) before treating this as a High/Critical theft finding.

### Likelihood Explanation
High likelihood of triggerability: contract deployment via `pallet-revive` and XCM execution via `pallet_xcm::execute`/`send` are both ordinary, unprivileged, already-enabled user entry points on the Asset Hub Westend runtime, and `IsLocalAccountKey20` performs no registry check, so no governance action or privileged setup is required to make the transactor treat an attacker's contract as a legitimate ERC20 asset.

### Recommendation
Do not rely solely on the counterparty contract's self-reported boolean return to determine withdrawal/deposit success or amount. At minimum:
- Restrict `ERC20Matcher`/`IsLocalAccountKey20` to a governance- or registry-approved allowlist of ERC20 contract addresses (mirroring how `TrustBackedAssetsConvertedConcreteId`/`ForeignAssetsConvertedConcreteId` require registered asset ids), rather than accepting any `AccountKey20` location.
- Independently verify actual balance movement (e.g., read `balanceOf` before and after the `transfer()` call, or require and check the `Transfer` event) instead of trusting only the decoded return value, closing the same class of "trust attacker-controlled input for fee/value determination" bug that Maple Labs was told to fix by adding an authoritative check rather than trusting `lender_`-supplied data.

### Proof of Concept
Verified statically by reading the transactor and matcher source (evidence cited above): `IsLocalAccountKey20::contains` matches unconditionally, `ERC20Transactor::{withdraw,deposit}_asset_with_surplus` gate success purely on `return_value.did_revert()` and `IERC20::transferCall::abi_decode_returns_validate(&return_value.data)` with no balance-delta verification. I did not execute a live Rust/FRAME integration test against the real XCM/pallet-revive boundary (no test harness run was performed), and I could not, within the remaining iterations, confirm the downstream fee-trader/asset-conversion path needed to demonstrate concrete extraction of another party's funds — this final step is unconfirmed and should be validated by a background engineering session with a local `pallet_xcm::execute` + `pallet-revive` integration test deploying a fake ERC20 contract that always returns `true` from `transfer()`, executing `WithdrawAsset`/`DepositAsset` against it, and asserting the `AssetsInHolding` credit versus the real (unchanged) contract balance.

### Citations

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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L159-207)
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
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L253-298)
```rust
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
```
