### Title
`ERC20Transactor::withdraw_asset_with_surplus` credits `AssetsInHolding` with the nominal transfer amount instead of the actual amount received by the checking account, breaking the 1:1 escrow invariant for fee-on-transfer/rebasing ERC20 tokens - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
The `ERC20Transactor` (used as an XCM `AssetTransactor` on Asset Hub Westend, wired in `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`) escrows ERC20 tokens into a `TransfersCheckingAccount` by calling the token's `transfer()` function, then unconditionally credits the XCM `AssetsInHolding` accounting with the *nominal requested amount*, not the amount the checking account actually received. This is functionally the same invariant violation described in the Nibiru report: an assumed 1:1 relationship between an escrow account's real ERC20 balance and its accounted representation (there `bank coin`, here `AssetsInHolding`), which breaks for ERC20 tokens whose balance changes are not exactly equal to the nominal transfer amount (fee-on-transfer tokens, rebasing tokens, or any ERC20 with non-standard transfer semantics). [1](#0-0) 

### Finding Description
`withdraw_asset_with_surplus` performs the ERC20 escrow by calling `IERC20::transferCall` from the user to `TransfersCheckingAccount`, using the nominal `amount` derived from `Matcher::matches_fungibles(what)`: [2](#0-1) 

After the call, the code only checks whether the contract reverted and whether the ERC20 `transfer` returned `true`/`false`. If it returned `true`, it unconditionally credits `AssetsInHolding` with the full nominal `amount`, regardless of what was actually deposited into `TransfersCheckingAccount`: [3](#0-2) 

There is no balance-before/balance-after check on the checking account (unlike, e.g., Nibiru's own `convertCoinToEvmBornERC20`, which explicitly reads `actualSentAmount` from the ERC20 balance delta). This means:
- For a fee-on-transfer ERC20, the checking account receives `amount - fee`, but `AssetsInHolding` records `amount`.
- For a rebasing ERC20 whose balance can change between the withdraw call and a later deposit, or whose `transfer()` doesn't move exactly `amount` net of internal rebase mechanics, the same discrepancy occurs.

The `deposit_asset_with_surplus` side then trusts this over/under-stated `AssetsInHolding` amount and issues `IERC20::transferCall` for that same nominal `amount` from the checking account to the beneficiary: [4](#0-3) 

Because multiple users' ERC20 balances are pooled into the same `TransfersCheckingAccount`, an under-collection from one user's fee-on-transfer/rebasing withdrawal degrades the checking account's real balance relative to the sum of nominal `AssetsInHolding` amounts accounted for across all in-flight XCM operations for that asset. This is exactly the invariant Nibiru's finding describes: escrow real balance vs. accounted balance is assumed 1:1 but is not guaranteed for tokens with balance changes outside of transfers.

### Impact Explanation
Two symmetric failure modes match the Nibiru report exactly:
1. If the token deducts a fee on transfer (or negatively rebases) between withdrawal and a later `deposit_asset_with_surplus` for that or another user, the checking account can run short of tokens, causing `IERC20::transferCall` for `amount` to return `false` and `XcmError::FailedToTransactAsset` — a deterministic, permanent failure to fulfill deposits for legitimately-accounted holding balances (funds effectively stuck/undeliverable in XCM terms).
2. If the token positively rebases while held in `TransfersCheckingAccount`, the surplus balance is never accounted for in `AssetsInHolding` and is permanently unreachable via the XCM accounting path (leaked value, matching the "escrow surplus stuck" scenario in the report).

Because `TransfersCheckingAccount` is a shared pooled account for *all* users of that ERC20 asset class, an under/over-collection by one XCM operation can affect the ability of *other* unrelated users' XCM asset transfers involving the same token to complete, which is a stronger-than-single-user integrity issue on shared escrow accounting.

### Likelihood Explanation
This requires the ERC20 contract registered via the XCM `Matcher` (i.e. matched as an `AccountKey20` fungible asset for Asset Hub's XCM config) to have non-standard transfer semantics — fee-on-transfer or balance changes outside of transfers (rebasing). The transactor itself imposes no restriction preventing arbitrary/permissionlessly-deployed ERC20 contracts (via `pallet-revive`) from being used this way, and any signed user can trigger `withdraw_asset_with_surplus`/`deposit_asset_with_surplus` through ordinary, unprivileged XCM instructions (`WithdrawAsset`/`DepositAsset`) executed via `pallet_xcm::execute`/`transfer_assets`. No privileged role or governance action is required — only that such a token is used with this transactor. Likelihood of triggering the underlying bug is contingent on whether Asset Hub actually registers/matches such non-standard ERC20 tokens through this transactor in production configuration, which I could not fully confirm from the available index (the exact `Matcher`/asset-registration policy in `xcm_config.rs` for `ERC20Transactor` was only partially visible before running out of iterations).

### Recommendation
In `withdraw_asset_with_surplus`, measure the checking account's ERC20 balance before and after the `transfer` call (as Nibiru's own `convertCoinToEvmBornERC20` does with `actualSentAmount`) and credit `AssetsInHolding` with the actual delta rather than the nominal `amount`. Symmetrically, in `deposit_asset_with_surplus`, verify the beneficiary's actual received balance delta matches what is deducted from the holding, and propagate any shortfall/surplus back into XCM accounting (or reject transfers for tokens exhibiting such non-standard behavior, e.g., by restricting the `Matcher`/asset registration policy to well-behaved ERC20 tokens only).

### Proof of Concept
I was unable to complete a full local FRAME/XCM integration reproduction within the available iterations. What is established from static code review:
- `withdraw_asset_with_surplus` and `deposit_asset_with_surplus` in `erc20_transactor.rs` never read the checking account's ERC20 balance before/after the `transfer` call; they trust the nominal `amount` and the boolean return value only [5](#0-4) .
- `ERC20Transactor` is referenced and wired into `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`, and `CheckingAccount`/`TransfersCheckingAccount` also appear in `cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs`, confirming this transactor is part of the production Asset Hub Westend XCM configuration [6](#0-5) .
- I could not confirm within the remaining iterations (a) the exact `Matcher` policy that determines which ERC20 contracts are eligible for this transactor on Asset Hub Westend (i.e., whether fee-on-transfer/rebasing tokens could realistically be registered), and (b) whether a full integration test exercising a deliberately non-standard ERC20 (fee-on-transfer or rebasing) against this transactor exists or was run. These would be required to move this from a "supported design gap" finding to a demonstrated exploit with concrete state deltas and attacker cost, per the reproduction requirements. A background Devin session with repository and terminal access would be needed to write and execute a minimal `pallet-revive` fixture ERC20 with fee-on-transfer semantics, register it via the Asset Hub Westend XCM `Matcher`, and run a withdraw/deposit XCM roundtrip to demonstrate the discrepancy between `AssetsInHolding` accounting and the checking account's real balance.

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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L248-266)
```rust
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
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L25-37)
```rust
use asset_hub_westend_runtime::{
	staking, xcm_config,
	xcm_config::{
		bridging, CheckingAccount, LocationToAccountId, StakingPot,
		TrustBackedAssetsPalletLocation, UniquesConvertedConcreteId, UniquesPalletLocation,
		WestendLocation, XcmConfig,
	},
	AllPalletsWithoutSystem, AssetRewards, Assets, Balances, Block, Executive, ExistentialDeposit,
	ForeignAssets, ForeignAssetsInstance, MetadataDepositBase, MetadataDepositPerByte,
	ParachainSystem, PolkadotXcm, Proxy, Revive, Runtime, RuntimeCall, RuntimeEvent, RuntimeOrigin,
	SessionKeys, ToRococoXcmRouterInstance, TrustBackedAssetsInstance, TxExtension,
	UncheckedExtrinsic, Uniques, WeightToFee, XcmpQueue,
};
```
