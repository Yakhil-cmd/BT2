## Title
`ERC20Transactor::deposit_asset_with_surplus` credits XCM holding for the full nominal amount without verifying the actual ERC20 balance delta, breaking accounting for fee-on-transfer / non-standard ERC20 tokens - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

## Summary
`ERC20Transactor` is a `TransactAsset` implementation wired into Asset Hub Westend's XCM configuration (`cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`) that bridges XCM asset handling to arbitrary ERC20 contracts deployed via `pallet-revive`, using raw Solidity `transfer()` calls executed through `pallet_revive::Pallet::<T>::bare_call`. Both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus` assume that a successful ERC20 `transfer()` call (returning `true`, not reverted) moved exactly `amount` tokens, and unconditionally construct/consume XCM holding credits for that nominal `amount` rather than measuring the actual balance change of the sender/receiver.

## Finding Description
In `withdraw_asset_with_surplus` (`cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs:150-216`), the code calls the ERC20 contract's `transfer` function to move tokens from `who` to a "checking account," then, if the call returns `true`, credits the XCM holding register with the requested `amount`:
```rust
Ok((
    AssetsInHolding::new_from_fungible_credit(
        what.id.clone(),
        Box::new(Erc20Credit(amount)),
    ),
    surplus,
))
``` [1](#0-0) 

Symmetrically, `deposit_asset_with_surplus` (lines 225-306) transfers the ERC20 `amount` from the checking account to the beneficiary and, as long as the call succeeds and doesn't revert, treats the deposit as fully successful:
```rust
match IERC20::transferCall::abi_decode_returns_validate(&return_value.data) {
    Ok(true) => {
        tracing::trace!(...);
        Ok(surplus)
    },
``` [2](#0-1) 

Neither function reads the ERC20 contract's `balanceOf` before and after the transfer to confirm the actual amount moved. This is precisely the missing check identified in the original report: an ERC20 contract that charges a transfer fee, rebases, or otherwise delivers less than `value` to the recipient (while still returning `true` and not reverting) will cause the transactor to record more tokens in the XCM holding register (or believe more was deposited to the beneficiary) than were actually moved. Because `Erc20Credit`'s own comment explicitly states: "This type implements the necessary imbalance accounting traits but does not perform runtime-level balance enforcement... the actual balance constraints are enforced by the ERC20 smart contract itself rather than the runtime" [3](#0-2) , the runtime has no independent verification and fully trusts the external contract's return value and the nominal `amount` for its ledger of "credited" XCM assets.

Any user who registers such an ERC20 token as a `ForeignAssets`-tracked / XCM-transactable asset (or any Ethereum-side contract with fee-on-transfer semantics bridged through this transactor, e.g. via the ERC20 transactor path used for revive-based tokens) can cause XCM holding accounting to diverge from actual on-chain ERC20 balances. This mirrors the reported class of bug ("fee-on-transfer token not supported properly") but the concrete boundary here is the XCM executor + `pallet-revive` bridging code, not an EVM contract directly.

## Impact Explanation
This is a genuine cross-boundary accounting gap: XCM's holding register (used to compute what can subsequently be deposited/forwarded/refunded within the same XCM program) can become inflated relative to the real ERC20 balance held by the `TransfersCheckingAccount`. Depending on how holdings are later spent (e.g. `DepositAsset`, `InitiateTransfer`, refunds), this could allow a party controlling such a token to cause `deposit_asset_with_surplus` to be invoked for more than the checking account can actually cover, or to have holdings tracked that don't correspond to a redeemable balance — a genuine value/integrity mismatch between XCM's internal ledger and the real asset. This is comparable in severity/nature to a Medium-severity accounting bug, since it does not directly let an unprivileged attacker steal from the runtime's own native assets, but it does corrupt the invariant that "XCM holding == real underlying asset balance," specifically for one class of externally-controlled asset (arbitrary Solidity ERC20 contracts, deployable by anyone via `pallet-revive`).

## Likelihood Explanation
Likelihood depends on this transactor actually being reachable for attacker-deployed contracts. The transactor is generic over `Matcher: MatchesFungibles<H160, u128>` — whether arbitrary user-deployed `pallet-revive` contracts can be matched as XCM-transactable assets (versus only a curated allow-list of registered tokens) needs to be verified against `AssetHubWestend`'s specific `Matcher` configuration in `xcm_config.rs`, which I was unable to fully confirm before running out of tool budget. If only privileged/root-registered tokens can use this transactor, likelihood is lower (limited attack surface); if any deployed ERC20 contract that a user controls the transfer-fee logic of can be registered as a transactable asset by a normal (non-privileged) flow, likelihood is materially higher.

## Recommendation
`withdraw_asset_with_surplus` and `deposit_asset_with_surplus` should measure the actual token balance delta of the relevant accounts (via `balanceOf` before/after the `transfer` call, or by using `transferFrom`-style patterns with explicit balance verification) rather than trusting the nominal `amount` and the boolean return value alone. The XCM holding credit/debit should reflect the verified actual amount moved, not the requested amount.

## Proof of Concept
Not executed. I could not run a concrete Rust/FRAME or XCM integration test within the available time/tool budget to demonstrate the exploit end-to-end (e.g., deploying a fee-on-transfer Solidity contract via `pallet-revive`, registering it as an XCM-matchable fungible asset in `AssetHubWestend`'s `Matcher`, and driving a `WithdrawAsset`/`DepositAsset` XCM program through `xcm_executor` to show the holding register diverges from the real ERC20 balance). I was also unable to fully confirm, before exhausting tool calls, whether `AssetHubWestend`'s `Matcher` configuration for `ERC20Transactor` restricts matchable assets to privileged/root-registered tokens only, which materially affects whether this is reachable by an unprivileged attacker. This should be verified with a live Devin session with full repository access and the ability to run the emulated-chain integration test harness (`cumulus/parachains/integration-tests/emulated/...`) before treating this as a confirmed, bounty-eligible finding.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L73-89)
```rust
/// A minimal imbalance tracking type that holds an ERC20 token amount.
///
/// This type implements the necessary imbalance accounting traits but does not perform
/// runtime-level balance enforcement. It's used to track ERC20 token amounts within XCM
/// asset holdings, where the actual balance constraints are enforced by the ERC20 smart
/// contract itself rather than the runtime.
struct Erc20Credit(u128);
impl UnsafeConstructorDestructor<u128> for Erc20Credit {
	fn unsafe_clone(&self) -> Box<dyn ImbalanceAccounting<u128>> {
		Box::new(Erc20Credit(self.0))
	}
	fn forget_imbalance(&mut self) -> u128 {
		let amount = self.0;
		self.0 = 0;
		amount
	}
}
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L185-203)
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
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L270-280)
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
```
