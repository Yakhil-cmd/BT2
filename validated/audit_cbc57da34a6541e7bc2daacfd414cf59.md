Confirmed: any Ethereum-style contract address `AccountKey20 { key, network: None }` located under `Location { parents: 0 }` is matched permissionlessly by `ERC20Matcher` (per prdoc `pr_7762`), so any user can deploy an arbitrary fee-on-transfer ERC20 via `pallet-revive` and immediately use it through XCM `WithdrawAsset`/`DepositAsset` on Asset Hub Westend. This confirms unprivileged reachability into `ERC20Transactor`.

### Title
`ERC20Transactor` credits the requested `amount` instead of the ERC20 contract's actual delivered balance, breaking accounting for fee-on-transfer/deflationary tokens - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` invoke `IERC20::transfer` on an arbitrary smart contract and, as long as the call returns `true`/does not revert, unconditionally treat the full requested `amount` as having moved. Neither function checks the checking account's or beneficiary's actual `balanceOf` delta. This is the exact bug class from the report: the caller assumes `transfer(amount)` moves `amount`, which is false for fee-on-transfer/deflationary ERC20 tokens.

### Finding Description
`withdraw_asset_with_surplus` calls the ERC20 contract's `transfer(checking_address, amount)` via `pallet_revive::Pallet::<T>::bare_call` and, on a `true`/non-reverted return, constructs `AssetsInHolding::new_from_fungible_credit(what.id.clone(), Box::new(Erc20Credit(amount)))` using the originally requested `amount`, not the amount the checking account actually received: [1](#0-0) 

Symmetrically, `deposit_asset_with_surplus` calls `transfer(beneficiary, amount)` from the checking account and, on success, treats the deposit as fully consumed: [2](#0-1) 

The struct-level comment explicitly documents this design assumption: "the actual balance constraints are enforced by the ERC20 smart contract itself rather than the runtime" — i.e. the runtime never independently verifies token movement: [3](#0-2) 

Any account can deploy an arbitrary ERC20 contract via `pallet_revive` (permissionless contract deploy is already enabled functionality) and reference it in XCM via `AccountKey20 { key, network: None }` under `Location { parents: 0 }`, which is exactly the design purpose of `ERC20Matcher`/`ERC20Transactor` introduced for Asset Hub Westend: [4](#0-3) [5](#0-4) 

If the contract implements a transfer fee (deducting `fee` on every `transfer` call and still returning `true`), then:
- On withdraw: the checking account only receives `amount - fee` in real ERC20 balance, but the XCM holding records `amount`.
- On deposit: the executor will attempt to move the inflated `amount` out of the checking account. If the checking account's real ERC20 balance (accumulated from prior/other withdrawals of the same token) is less than the inflated `amount`, `transfer` reverts and the deposit legitimately fails/traps. But if the checking account happens to have surplus real balance from other operations on the same asset (e.g. concurrent XCM programs, or fees not being 100%), a `deposit_asset` call can drain more real tokens from the checking account than were ever credited to that particular sender's holding, effectively letting one user's XCM holding consume real balance that belongs to another user's pending/parallel withdraw of the same ERC20 asset — a cross-message accounting break rather than a simple local revert, because unlike the Solidity CollateralManager case there is no atomic single-function revert guarding the whole flow; withdraw and deposit happen in separate `TransactAsset` calls potentially across different XCM instructions/messages.

This differs from the general `fungibles`/`fungible` adapters (`FungiblesTransferAdapter`, `FungibleTransferAdapter`), which delegate to trusted in-runtime pallets (`pallet_assets`, `pallet_balances`) whose `transfer`/`do_transfer` functions return the *actual* transferred amount and are checked elsewhere (e.g. `substrate/frame/asset-conversion/ops/src/lib.rs:209-219` explicitly asserts `balance1 == T::Assets::transfer(...)`, guarding this exact bug class for native pallets). `ERC20Transactor` is the one adapter in this codebase that trusts an arbitrary, attacker-controlled external contract's self-reported return value instead of verifying real balance deltas.

### Impact Explanation
Medium: this is an accounting-desync issue confined to the ERC20-asset checking account's ledger for a specific attacker-deployed contract, not a direct drain of native DOT/system-asset funds, and not an unbounded issuance of a "real" asset. Its impact is scoped to whatever ERC20 tokens are routed through `ERC20Transactor`/`ERC20TransfersCheckingAccount`, matching the Medium severity of the original report (a specific class of token misbehaves with a transfer helper that assumes exact-amount semantics), rather than Critical/High native-asset theft.

### Likelihood Explanation
Reachable by any unprivileged account: contract deployment via `pallet-revive` is a normal enabled feature, and `ERC20Matcher`/`ERC20Transactor` are permissionlessly triggered for any `AccountKey20` location, as intended by design (`prdoc/stable2506/pr_7762.prdoc`). No governance, root, or privileged role is required. However, exploiting it to actually extract value beyond the attacker's own deposited tokens further requires either overlapping concurrent operations on the same checking-account balance for the same ERC20 contract, or careful sequencing — this reduces practical likelihood compared to a trivial single-call theft.

### Recommendation
In `ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, read the relevant account's ERC20 `balanceOf` before and after the `transfer` call (or use `balanceOf(checking_address)`/`balanceOf(beneficiary)` deltas) instead of trusting the requested `amount`, and construct `Erc20Credit`/treat the deposit as consumed using the actual measured delta, mirroring the `balanceBefore`/`balanceAfter` pattern recommended in the original report.

### Proof of Concept
No executable PoC was run against this codebase (no filesystem/terminal access in this session); this analysis is a static-code-reachability analog based on: (1) confirmed permissionless contract-deploy plus `ERC20Matcher` wiring in `asset-hub-westend` (`prdoc/stable2506/pr_7762.prdoc`, `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs:221-237`), and (2) the unconditional `amount`-based crediting shown at `erc20_transactor.rs:195-204` and `:253-280`. A full reproduction would require writing a minimal fee-on-transfer Solidity/YUL contract compiled for `pallet-revive`, deploying it via `bare_instantiate` (as already exercised by the existing test `smart_contract_does_not_return_bool_fails` in `cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs:2026-2081`, which is a suitable harness template), then issuing a `WithdrawAsset`/`DepositAsset` XCM program and asserting the checking account's real `balanceOf` versus the `AssetsInHolding` amount diverge. This was not executed in this session; the finding rests on code inspection, not a confirmed live execution trace.

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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L195-204)
```rust
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
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L253-280)
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
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs (L221-237)
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
```

**File:** prdoc/stable2506/pr_7762.prdoc (L4-19)
```text
title: ERC20 Asset Transactor

doc:
  - audience: Runtime Dev
    description: |
      This PR introduces an Asset Transactor for dealing with ERC20 tokens and adds it to Asset Hub
      Westend.
      This means asset ids of the form `{ parents: 0, interior: X1(AccountKey20 { key, network }) }` will be
      matched by this transactor and the corresponding `transfer` function will be called in the
      smart contract whose address is `key`.
      If your chain uses `pallet-revive`, you can support ERC20s as well by adding the transactor, which lives
      in `assets-common`.
  - audience: Runtime User
    description: |
      This PR allows ERC20 tokens on Asset Hub to be referenced in XCM via their smart contract address.
      This is the first step towards cross-chain transferring ERC20s created on the Hub.
```
