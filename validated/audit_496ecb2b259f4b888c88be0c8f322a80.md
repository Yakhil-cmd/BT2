### Title
ERC20 `TransactAsset` transactor credits/debits the XCM holding register by the requested `amount` instead of the ERC20 contract's actual transferred amount, allowing fee-on-transfer/rebasing ERC20 tokens to desynchronize the checking-account backing from XCM-accounted value - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `ERC20Transactor::deposit_asset_with_surplus` invoke an arbitrary ERC20 contract's `transfer()` and, upon a `true` boolean return value, unconditionally treat the *requested* `amount` as the amount moved, crediting the XCM `AssetsInHolding` register (in `withdraw`) or reporting success (in `deposit`) with that nominal `amount`. Neither function checks the checking account's/beneficiary's actual ERC20 balance before/after the call, mirroring exactly the prePO `Collateral.sol` bug class where a fee-on-transfer ERC20 causes the caller-assumed amount to diverge from the actually-received amount.

### Finding Description
`withdraw_asset_with_surplus` transfers `amount` of an ERC20 token from a user (`who`) to a fixed `TransfersCheckingAccount` via a `bare_call` to the token's `transfer(to, value)` and, if the returned boolean is `true`, immediately mints an `Erc20Credit(amount)` into the XCM holding register: [1](#0-0) 

This is the ERC20 analog of the `Collateral.sol` `deposit()` flow in the reported bug: the caller trusts `transferFrom`'s boolean success and uses the *requested* amount for downstream accounting, instead of measuring the checking account's real balance delta. If the ERC20 contract deducts a fee on transfer (or is a rebasing token), the `TransfersCheckingAccount`'s real balance increases by `amount - fee`, but the XCM holding register (and therefore any subsequent `DepositAsset`, reserve/teleport bookkeeping, or destination-chain minting derived from this credited amount) is inflated by the fee amount that never actually arrived.

Symmetrically, `deposit_asset_with_surplus` transfers `amount` from `TransfersCheckingAccount` to the beneficiary and reports success purely from the boolean `true` return of `transfer()`: [2](#0-1) 

If the token deducts a fee, the beneficiary receives less than `amount`, matching item (3) of the original report ("the user will receive less baseToken amount than what they should receive") — yet the executor's weight/asset accounting proceeds as if the full `amount` was delivered, with no reconciliation against the checking account's real balance change.

Both functions rely exclusively on the boolean-success semantics of `IERC20::transferCall::abi_decode_returns_validate`, never comparing pre/post balances of the checking account (`TransfersCheckingAccount::get()`) as recommended in the original finding's remediation ("record balance before and after; use actual delta").

### Impact Explanation
The `TransfersCheckingAccount` is the custodial/reserve account backing all XCM-held representations of a given ERC20 asset moving through this transactor (analogous to `Collateral`'s baseToken reserve). If an asset registered with `ERC20Transactor`/`Matcher::matches_fungibles` corresponds to a fee-on-transfer or rebasing ERC20 contract:
- On `withdraw_asset_with_surplus`, the XCM holding register is credited with more than what the checking account actually received, over-crediting the value available for subsequent `DepositAsset`/reserve-transfer operations — a reserve-backing deficit for the checking account, analogous to unbacked issuance.
- On `deposit_asset_with_surplus`, the beneficiary silently receives less than the nominal amount removed from the checking account's ledger, permanently losing the fee difference with no error surfaced to the XCM program.

This is the same violated invariant as the prePO report ("assumed transferred amount == requested amount for an externally-controlled ERC20"), transplanted onto a Polkadot-SDK reserve/checking-account transactor rather than a vault contract.

### Likelihood Explanation
Reachability depends entirely on the runtime operator's asset registration/`Matcher` configuration: this vulnerability is only exploitable if a fee-on-transfer or rebasing ERC20 contract is permitted to be registered as a `ERC20Transactor`-backed fungible asset reachable via ordinary user-initiated XCM (e.g., `pallet_xcm::transfer_assets`/reserve transfer of that asset). The transactor is wired into a live runtime (`cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`), so the code path is deployed, but I was unable to fully confirm from the available index whether asset registration in that runtime is permissionless or restricted to a privileged authority (e.g., root/governance-controlled asset creation) — this materially affects whether an "attacker has no privileged role" precondition is satisfiable. Because the finding's `SECURITY.md`/`RESEARCHER.md` guidance requires the attacker to have no privileged prerequisites, and typical ERC20-asset registration for XCM transactors is usually gated behind a governance/root-controlled registry (similar to how `pallet_assets::force_create`/foreign-asset registration is root-only elsewhere in this codebase), the likelihood that an ordinary unprivileged user can introduce an arbitrary fee-on-transfer ERC20 into this transactor's scope is uncertain and likely low without further verification of `Matcher`/asset-registration permissions in `asset-hub-westend/src/xcm_config.rs`.

### Recommendation
In both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, record the `TransfersCheckingAccount`'s (or beneficiary's) ERC20 balance immediately before and after the `bare_call` to `transfer()`, and use the measured delta — not the requested `amount` — both for the `Erc20Credit` minted into `AssetsInHolding` and for determining success/failure of the deposit. If the delta is smaller than `amount`, either fail the operation explicitly or credit/report only the actual delta, consistent with the FRAME `fungible`/`fungibles::transfer` convention of returning the *actual* transferred amount (as enforced elsewhere in this codebase, e.g. `substrate/frame/asset-conversion/ops/src/lib.rs` which asserts `balance1 == T::Assets::transfer(...)`).

### Proof of Concept
No local reproduction was executed. This report is a structural code-review analog based on:
- Reading `cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs` in full, confirming the missing balance-before/after check in both `withdraw_asset_with_surplus` (lines 150-216) and `deposit_asset_with_surplus` (lines 225-306).
- Confirming the transactor is referenced in a real runtime config (`cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`) and has an associated test file (`cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs`), indicating deployment but not conclusively resolving asset-registration privilege requirements.
- Comparing against the FRAME idiom elsewhere in this codebase (`substrate/frame/asset-conversion/ops/src/lib.rs` lines 209-231) which explicitly checks `T::Assets::transfer(...)` return value against the intended amount and errors with `Error::<T>::PartialTransfer` if it diverges — a pattern absent in `erc20_transactor.rs`.

Given the unresolved question of whether unprivileged users can register/select a fee-on-transfer ERC20 asset for this transactor, I cannot assert this as a confirmed, reachable, unprivileged-attacker exploit at Medium/High bounty-eligible confidence; it is reported as a structural analog requiring further verification of asset-registration privilege in `asset-hub-westend/src/xcm_config.rs` before treating it as an accepted finding.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L166-203)
```rust
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
