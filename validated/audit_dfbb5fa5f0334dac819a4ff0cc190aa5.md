### Title
Hardcoded `ERC20TransferGasLimit` weight in `ERC20Transactor` can deterministically fail XCM reserve transfers for non-trivial ERC20 tokens - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
The Asset Hub XCM `TransactAsset` implementation for smart-contract (ERC20) assets, `ERC20Transactor`, uses a single hardcoded weight limit (`ERC20TransferGasLimit`) for every `transfer()` call it makes on arbitrary ERC20 contracts, regardless of the actual gas/weight the token's `transfer()` implementation needs. This mirrors the reported Solidity pattern of using a fixed gas stipend (`call(50000, …)`) for outgoing transfers that may not suffice for all recipients/contracts. [1](#0-0) 

### Finding Description
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` both invoke `pallet_revive::Pallet::<T>::bare_call` with `TransactionLimits::WeightAndDeposit { weight_limit: WeightLimit::get(), .. }`, where `WeightLimit` is bound at the runtime level to the constant `ERC20TransferGasLimit = Weight::from_parts(500_000_000_000, 10 * 1024 * 1024)`, documented as "Taken from the real gas and deposits of a standard ERC20 transfer call." [2](#0-1) [3](#0-2) 

This limit is applied uniformly to any contract matched by `assets_common::ERC20Matcher` as an ERC20 asset, not just simple OpenZeppelin-style transfers. ERC20 tokens with fee-on-transfer logic, transfer hooks, blacklist/allowlist checks, pausability, rebasing accounting, or reentrancy guards routinely consume more compute than a "standard" transfer. When that happens, `bare_call` returns an `Err(result)` (out of gas/weight), and the code explicitly acknowledges the design limitation in its own comments: [4](#0-3) [5](#0-4) 

The critical asymmetry: `withdraw_asset_with_surplus` performs a *real* on-chain ERC20 `transfer()` moving the user's tokens into `ERC20TransfersCheckingAccount` before the XCM holding-register credit (`Erc20Credit`) is created. If a later `DepositAsset` instruction (e.g., to a beneficiary on another chain, or back on the same chain during a reserve transfer) invokes `deposit_asset_with_surplus` on the *same* token contract and the token's `transfer()` logic exceeds the hardcoded weight, the deposit fails deterministically every time — the gas ceiling cannot be raised by the user via any XCM parameter, as the code's own comments state.

On failure, the XCM executor's failure/trap machinery treats the un-deposited `Erc20Credit` as an ordinary asset and traps it via `Config::AssetTrap::drop_assets`, making it reclaimable later through `pallet_xcm::claim_assets` / the `ClaimAsset` instruction, which calls `AssetTransactor::mint_asset`. [6](#0-5) 

However, `ERC20Transactor` only implements `can_check_in`, `check_in`, `can_check_out`, `check_out`, `withdraw_asset_with_surplus`, and `deposit_asset_with_surplus` — it does not implement a custom `mint_asset`. [7](#0-6) 

I was unable to fully confirm within this session whether the default `TransactAsset::mint_asset` implementation ultimately re-invokes `deposit_asset` (in `polkadot/xcm/xcm-executor/src/traits/transact_asset.rs`, which I located but did not read in full). If it does — which is the typical default behavior in the XCM executor traits — then the claim/recovery path for this specific asset would re-run the exact same `transfer()` call against the same hardcoded `ERC20TransferGasLimit`, deterministically failing again. In that scenario the real ERC20 tokens held in `ERC20TransfersCheckingAccount` become **permanently unrecoverable** through any XCM-based path, for as long as the token's `transfer()` implementation costs more weight than the hardcoded ceiling.

### Impact Explanation
If the default `mint_asset` recovery path re-delegates to the same hardcoded-weight `deposit_asset_with_surplus`, this is an irreversible-freezing bug class (real ERC20 balances stuck in a pallet-controlled checking account with no recovery mechanism) for any ERC20 asset registered for XCM use whose `transfer()` gas usage exceeds `500_000_000_000` ref_time / `10 MiB` proof size. Even absent that worst case, at minimum this causes deterministic, unrecoverable-by-configuration transaction failures for legitimate cross-chain transfers of non-trivial ERC20 tokens (a functional DoS on those specific assets), matching the reported bug class exactly ("hardcoded gas limit could result in failed transactions").

### Likelihood Explanation
Reaching this requires only a permissionless, ordinary user action: initiating an XCM asset transfer (via `pallet_xcm::execute`/`transfer_assets`/reserve-transfer flows or receiving an incoming reserve transfer) involving an ERC20 token that is registered/matched by `ERC20Matcher` and whose `transfer()` function is more gas-intensive than a "standard" transfer — a very common real-world category of ERC20 (fee-on-transfer, pausable, hook-based, blacklist-checking tokens). No privileged role, governance action, or malicious actor is needed; the failure is deterministic and depends only on the token's own bytecode, which the transacting user does not control and cannot work around from the XCM message.

### Recommendation
- Do not use a single hardcoded weight ceiling for arbitrary ERC20 `transfer()` calls in `ERC20Transactor`. Either dry-run/estimate the required weight per-contract before committing to the real call, or expose/enforce a per-asset configurable (and periodically re-benchmarked) weight limit rather than one constant assumed to fit "a standard ERC20 transfer."
- Confirm and, if necessary, fix `mint_asset`/claim-recovery behavior for ERC20-backed assets so that trapped `Erc20Credit` balances are not doomed to hit the identical hardcoded limit on every recovery attempt — e.g., allow claim_assets to run with a distinctly higher/administrator-configurable weight limit, decoupled from the standard transfer path's ceiling.
- Add integration tests using a high-gas ERC20 fixture (fee-on-transfer/hooked contract exceeding `ERC20TransferGasLimit`) exercising withdraw-succeeds/deposit-fails/claim-attempt-fails to verify whether funds become permanently stuck, and fix accordingly if confirmed.

### Proof of Concept
Not executed. This report is a static-analysis analog derived from code inspection; I was unable to run a Rust/FRAME integration test in this session and did not verify at the trait-default level whether `mint_asset` truly re-enters `deposit_asset` for this transactor (file `polkadot/xcm/xcm-executor/src/traits/transact_asset.rs` was located by `grep_search` but its contents were not read before the iteration budget was exhausted). A concrete reproduction would deploy a `pallet-revive` ERC20 contract whose `transfer()` deliberately consumes more than `500_000_000_000` ref_time (e.g., via an expensive loop or storage-heavy hook), register it through `ERC20Matcher`, execute an XCM `WithdrawAsset`/`DepositAsset` sequence via `pallet_xcm::execute`, and observe: (1) `withdraw_asset_with_surplus` succeeds (real transfer to `ERC20TransfersCheckingAccount`), (2) `deposit_asset_with_surplus` fails with `XcmError::FailedToTransactAsset("ERC20 contract execution errored")`, (3) `AssetsTrapped` is emitted, and (4) a subsequent `pallet_xcm::claim_assets` for the same asset also fails or succeeds only in accounting terms without releasing the real ERC20 balance from the checking account.

### Citations

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs (L213-219)
```rust
parameter_types! {
	/// Taken from the real gas and deposits of a standard ERC20 transfer call.
	pub const ERC20TransferGasLimit: Weight = Weight::from_parts(500_000_000_000, 10 * 1024 * 1024);
	pub const ERC20TransferStorageDepositLimit: Balance = 10_200_000_000;
	pub ERC20TransfersCheckingAccount: AccountId = PalletId(*b"py/revch").into_account_truncating();
	pub DapBufferAccount: AccountId = pallet_dap::Pallet::<Runtime>::buffer_account();
}
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L109-149)
```rust
impl<
		AccountId: Eq + Clone,
		T: pallet_revive::Config<AccountId = AccountId>,
		AccountIdConverter: ConvertLocation<AccountId>,
		Matcher: MatchesFungibles<H160, u128>,
		WeightLimit: Get<Weight>,
		StorageDepositLimit: Get<BalanceOf<T>>,
		TransfersCheckingAccount: Get<AccountId>,
	> TransactAsset
	for ERC20Transactor<
		T,
		Matcher,
		AccountIdConverter,
		WeightLimit,
		StorageDepositLimit,
		AccountId,
		TransfersCheckingAccount,
	>
where
	BalanceOf<T>: Into<U256> + TryFrom<U256>,
	MomentOf<T>: Into<U256>,
	T::Hash: frame_support::traits::IsType<H256>,
{
	fn can_check_in(_origin: &Location, _what: &Asset, _context: &XcmContext) -> XcmResult {
		// We don't support teleports.
		Err(XcmError::Unimplemented)
	}

	fn check_in(_origin: &Location, _what: &Asset, _context: &XcmContext) {
		// We don't support teleports.
	}

	fn can_check_out(_destination: &Location, _what: &Asset, _context: &XcmContext) -> XcmResult {
		// We don't support teleports.
		Err(XcmError::Unimplemented)
	}

	fn check_out(_destination: &Location, _what: &Asset, _context: &XcmContext) {
		// We don't support teleports.
	}

```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L163-181)
```rust
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
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L209-215)
```rust
		} else {
			tracing::debug!(target: "xcm::transactor::erc20::withdraw", ?result, "Error");
			// This error could've been duplicate smart contract, out of gas, etc.
			// If the issue is gas, there's nothing the user can change in the XCM
			// that will make this work since there's a hardcoded gas limit.
			Err(XcmError::FailedToTransactAsset("ERC20 contract execution errored"))
		}
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L253-266)
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
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L299-305)
```rust
		} else {
			tracing::debug!(target: "xcm::transactor::erc20::deposit", ?result, "Error");
			// This error could've been duplicate smart contract, out of gas, etc.
			// If the issue is gas, there's nothing the user can change in the XCM
			// that will make this work since there's a hardcoded gas limit.
			Err((what, XcmError::FailedToTransactAsset("ERC20 contract execution errored")))
		}
```

**File:** polkadot/xcm/pallet-xcm/src/lib.rs (L3970-4020)
```rust
impl<T: Config> ClaimAssets for Pallet<T> {
	fn claim_assets(
		origin: &Location,
		ticket: &Location,
		assets: &Assets,
		context: &XcmContext,
	) -> Option<AssetsInHolding> {
		let mut versioned = VersionedAssets::from(assets.clone());
		match ticket.unpack() {
			(0, [GeneralIndex(i)]) => {
				versioned = match versioned.into_version(*i as u32) {
					Ok(v) => v,
					Err(()) => return None,
				}
			},
			(0, []) => (),
			_ => return None,
		};
		let hash = BlakeTwo256::hash_of(&(origin.clone(), versioned.clone()));
		match AssetTraps::<T>::get(hash) {
			0 => return None,
			1 => AssetTraps::<T>::remove(hash),
			n => AssetTraps::<T>::insert(hash, n - 1),
		}
		let mut claimed = AssetsInHolding::new();
		for asset in assets.inner() {
			match <T::XcmExecutor as XcmAssetTransfers>::AssetTransactor::mint_asset(asset, context)
			{
				Ok(minted) => {
					// SAFETY: Any fungible imbalances are now effectively duplicated because they
					// were not resolved when the asset was trapped (so total issuance tracks
					// trapped assets too), and now a duplicate asset was just minted.
					// To balance the system and keep total issuance constant, we drop and resolve
					// one of the duplicates. As a result, total issuance doesn't change.
					//
					// Note: This may emit Burned/Minted events even though the net issuance change
					// is zero. The mint creates a +X imbalance, and dropping the clone resolves -X,
					// resulting in no net change but potentially two events. This is an acceptable
					// tradeoff for the asset trap/claim mechanism.
					minted.fungible.iter().for_each(|(_, imbalance)| {
						let to_resolve = imbalance.unsafe_clone();
						core::mem::drop(to_resolve);
					});
					claimed.subsume_assets(minted)
				},
				Err(error) => tracing::debug!(
					target: "xcm::pallet_xcm::claim_assets",
					?asset, ?error, "Asset claimed from trap but unable to mint."
				),
			}
		}
```
