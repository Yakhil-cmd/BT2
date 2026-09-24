## Analog Found

### Title
ERC20Transactor assumes full-amount transfer for fee-on-transfer ERC20 tokens, corrupting the shared checking-account accounting - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `ERC20Transactor::deposit_asset_with_surplus` execute a `transfer()` call against an arbitrary user-deployed `pallet-revive` ERC20 contract and, upon seeing the ABI-encoded `true` return value, unconditionally credit/debit the XCM holding register with the *requested* `amount` rather than the amount actually moved. This is exactly the bug class in the report: for a fee-on-transfer token the recipient receives `amount - fee`, but the code's accounting still assumes `amount` was moved.

### Finding Description
`ERC20Matcher` (defined in [1](#0-0) ) matches *any* local `AccountKey20` location as a valid ERC20 asset id — i.e. any address of a contract a user has deployed via `pallet-revive`. `ERC20Transactor` is wired into the real Asset Hub Westend XCM configuration (confirmed present in `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`), so it is reachable from a normal, permissionless XCM program (e.g. `pallet_xcm::execute`, a local reserve-transfer, or `Transact`/`InitiateTransfer` involving the attacker's own ERC20 asset) — no privileged origin is required.

In `withdraw_asset_with_surplus`, the transactor calls the ERC20 contract's `transfer(to: checking_address, value: amount)` from the user's own account and, on success (`Ok(true)`), creates an `AssetsInHolding` credit of exactly `amount`: [2](#0-1) 

If the ERC20 contract implements a fee-on-transfer (or rebasing/deflationary) mechanic, the `TransfersCheckingAccount` actually receives `amount - fee`, but the XCM executor's holding register believes it holds the full `amount`. The check is only "did the call succeed / did it return `true`," never "did the checking account's balance increase by `amount`": [3](#0-2) 

Symmetrically, `deposit_asset_with_surplus` transfers `amount` out of the shared `TransfersCheckingAccount` to a beneficiary using the same "trust the boolean return" pattern: [4](#0-3) [5](#0-4) 

Because `TransfersCheckingAccount` is a single shared account used for *all* ERC20 assets routed through this transactor, a mismatch introduced by one user's fee-on-transfer token corrupts the checking account's real balance relative to what the runtime's XCM holding/accounting logic believes it should be able to deposit out again for that same asset. Unlike `pallet-assets`, where transfers are pure ledger arithmetic and cannot desync from external state, this transactor bridges to an external, attacker-controlled contract whose `transfer()` semantics are not guaranteed to move the full requested amount — precisely the invariant violated in the original report.

### Impact Explanation
For a given ERC20 asset with fee-on-transfer semantics:
- On withdraw, the checking account receives less than `amount`, but the holding register (and hence subsequent `DepositAsset` instructions to a beneficiary, possibly on a different chain via reserve/teleport semantics) is credited with the full `amount`.
- Subsequent `deposit_asset_with_surplus` calls for that same asset will then attempt to move `amount` out of the checking account. If the checking account's real balance for that asset has been topped up by other users' deposits, this second transfer will draw down other users' funds to make up the shortfall (again subject to any fee the token imposes on that transfer as well), or it will simply revert leaving XCM execution stuck/failed for legitimate users of that asset.
- This can result in silent value leakage from the shared checking account (funds effectively taken from other holders of the same asset) or deterministic failure of deposits for that whole asset class, since the checking account's tracked/implied balance never matches the actual on-chain ERC20 balance.

This does not enable unbacked issuance of a *native* system asset, and it is confined to ERC20 assets a user chooses to route through the transactor, so it is not a Critical-severity chain-halting or system-currency-inflation bug, but it is a genuine correctness/accounting break for a real, reachable, permissionless code path in a production Asset Hub XCM config — consistent with a Medium-severity classification, mirroring the original report.

### Likelihood Explanation
Likely to occur for any fee-on-transfer, rebasing, or otherwise non-standard ERC20 token deployed via `pallet-revive` and used through `ERC20Transactor` in ordinary XCM asset transfers. No governance, validator, or privileged action is needed — a user simply deploys such a contract and initiates a normal reserve-transfer/`execute` XCM program referencing it as the asset.

### Recommendation
In both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, read the ERC20 balance of the relevant account (`TransfersCheckingAccount` on withdraw, beneficiary on deposit) before and after the `transfer` call, and use the observed delta — not the requested `amount` — when constructing the `AssetsInHolding` credit or reporting success/failure to the XCM executor. If the delta is less than the requested amount, either fail the operation or adjust the holding register accordingly so the checking account's assumed and actual balances never diverge.

### Proof of Concept
Not independently executed against a running node; this analysis is based on static code review of `cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs` and its wiring into `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`, plus `ERC20Matcher` in `cumulus/parachains/runtimes/assets/common/src/lib.rs`. I was not able to fully verify, within the tool budget, the exact `AssetTransactors` tuple ordering/gating in `xcm_config.rs` (e.g., whether additional filters restrict which ERC20 contracts can be used) or trace a full end-to-end reserve-transfer test exercising a deliberately fee-on-transfer `pallet-revive` contract; a live/local integration reproduction (deploy a fee-on-transfer ERC20 via `pallet-revive`, then drive it through `pallet_xcm::execute`/reserve-transfer and assert checking-account/holding-register divergence) would be needed to fully confirm exploitability end-to-end.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/lib.rs (L157-160)
```rust
/// [`xcm_executor::traits::MatchesFungibles`] implementation that matches
/// ERC20 tokens.
pub type ERC20Matcher =
	MatchedConvertedConcreteId<H160, u128, IsLocalAccountKey20, AccountKey20ToH160, TryConvertInto>;
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L185-208)
```rust
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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L251-266)
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
