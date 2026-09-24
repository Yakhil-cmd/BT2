## Analysis

The Notional report's root cause — code that **blindly credits/assumes a fixed `amount`** was moved by a token transfer, without verifying the actual amount that arrived at the destination, causing accounting to diverge from reality when the token deducts a fee on transfer — has a direct analog in the Polkadot SDK's `ERC20Transactor`, which is wired into the real, permissionless XCM execution path on Asset Hub.

`ERC20Transactor` (used by `pallet-xcm`/XCM executor to move ERC20 tokens deployed as `pallet-revive` smart contracts) is included in `AssetTransactors` on Asset Hub Westend: [1](#0-0) 

Its `withdraw_asset_with_surplus` calls the ERC20 `transfer(checking_address, amount)` and, if the call did not revert and `transfer` returned `true`, unconditionally credits the *requested* `amount` (from the XCM `Asset`, fully attacker-controlled since any signed account can build a `WithdrawAsset`/XCM `execute`/`transfer_assets` program) into the XCM holding register, without ever checking the checking account's actual received balance: [2](#0-1) 

Symmetrically, `deposit_asset_with_surplus` transfers that same `amount` out of the checking account to the beneficiary: [3](#0-2) 

If the ERC20 token contract implements a fee-on-transfer (deducts a percentage/fixed fee on `transfer`, which is legal per the `IERC20` interface and returns `true` on success — this is exactly the OpenZeppelin `_update`/`transfer` pattern shown in `substrate/frame/revive/fixtures/contracts/external/openzeppelin/contracts/token/ERC20/ERC20.sol`, and nothing in `pallet-revive`/XCM enforces "no-fee" semantics on arbitrary user-deployed ERC20 contracts) then:
- On withdraw, the checking account's *actual* balance increases by `amount - fee`, but the XCM holding register is credited with the full `amount`.
- On deposit (e.g. the very same `DepositAsset` instruction, or a later leg of a reserve/teleport-style transfer, or after the amount is split/forwarded), the transactor attempts to `transfer(amount)` out of the checking account — but the checking account only has `amount - fee` (minus fees possibly accumulated over multiple such transfers), so `IERC20.transfer` either reverts or returns `false`, and `deposit_asset_with_surplus` returns `FailedToTransactAsset`.

This directly mirrors the Notional bug's mechanism: an accounting ledger (XCM holding / checking-account bookkeeping) is credited with the nominal amount requested rather than the amount actually received, and a later withdrawal step that requires the full nominal amount to be present reverts, permanently breaking that leg of the transfer (funds get stuck in holding / the XCM program fails, and repeated fee-on-transfer transactions cause the checking account's real balance to drift further below what the runtime believes it holds).

### Title
Fee-on-transfer ERC20 tokens desynchronize the `ERC20Transactor` checking-account balance from XCM holding accounting, causing deposits to permanently fail - (File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs)

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` credits the XCM holding register with the full nominal `amount` from an XCM `Asset` after calling `IERC20.transfer` on an arbitrary user-deployed ERC20 contract, without verifying that the checking account's balance actually increased by that amount. Any ERC20 token that deducts a fee on transfer (a legal, standard-compliant behavior; see the `_update` pattern in `ERC20.sol`) causes the checking account to receive less than `amount`. `deposit_asset_with_surplus` subsequently attempts to move the full nominal `amount` back out of the checking account, which reverts/fails because the checking account is short by the accumulated fee.

### Finding Description
`withdraw_asset_with_surplus` (`erc20_transactor.rs:150-216`) parses `(asset_id, amount)` from the XCM `Asset` via `Matcher::matches_fungibles`, calls the ERC20 `transfer(checking_address, amount)`, and — on success — constructs `AssetsInHolding::new_from_fungible_credit(what.id.clone(), Box::new(Erc20Credit(amount)))`, i.e. it trusts `amount` as the true amount now held by `TransfersCheckingAccount`, rather than reading the checking account's actual token balance before/after the call.

`deposit_asset_with_surplus` (`erc20_transactor.rs:225-306`) then transfers that same nominal `amount` out of the checking account to the beneficiary using `IERC20::transferCall { to: address, value: amount }`.

For a fee-on-transfer ERC20 token, the checking account's real balance after the withdraw-side transfer is `amount - fee`. The `Erc20Credit(amount)` imbalance object, however, still represents `amount` inside the XCM executor's holding register. When the executor later executes `DepositAsset`, it will try to deposit `amount` (or some portion of it) out of the checking account, but the checking account does not actually hold that much — the ERC20 `transfer` call underlying `deposit_asset_with_surplus` will revert or return `false` once the checking account's real balance is insufficient, and the whole XCM program fails with `FailedToTransactAsset`.

This is fully reachable by any signed, unprivileged account: registering/deploying an ERC20 contract via `pallet-revive` with fee-on-transfer semantics is a normal smart-contract deployment (no special permission), and then triggering a reserve transfer / `pallet_xcm::execute` / `transfer_assets` referencing that contract's location as the asset — which is the intended, documented use of `ERC20Transactor` (see wiring in `asset-hub-westend/src/xcm_config.rs`).

### Impact Explanation
Every XCM operation that withdraws a fee-on-transfer ERC20 token into the checking account and then attempts to deposit the *same* nominal amount out again will fail. Because the checking account is a single shared pooled account for all ERC20 transfers of that asset type through this transactor, repeated failed/partial transfers can leave the checking account's real balance permanently below what multiple in-flight/retried XCM programs assume is available, deterministically breaking deposit-side legs of transfers for that asset and stranding user funds mid-flight (withdrawn from the user but undeliverable to the beneficiary). This matches the "withdrawing/deposit process is broken" impact from the source report, scoped to Medium severity because it requires a token contract with non-standard fee-on-transfer behavior (analogous to the source finding's own Medium rating for the "unlikely scenario" of fee-on-transfer tokens), but the failure mode is deterministic and not attacker-privileged.

### Likelihood Explanation
Likelihood depends entirely on whether fee-on-transfer ERC20 contracts are deployed and referenced as XCM-transactable assets on chains that enable `ERC20Transactor` (currently Asset Hub Westend per the wiring found). Any user can deploy such a contract via `pallet-revive` and reference it in an XCM asset location; this needs no special privilege, matching the required threat model (no governance/validator/relayer trust needed).

### Recommendation
`withdraw_asset_with_surplus` should measure the checking account's actual ERC20 balance before and after the `transfer` call and credit the holding register with the *observed delta*, not the nominal `amount` requested. Alternatively, disallow/flag ERC20 assets for XCM transacting unless they are known not to implement fee-on-transfer semantics (e.g., via an allow-list maintained by governance), since the executor's holding-register accounting fundamentally assumes exact, lossless transfers.

### Proof of Concept
No executable local reproduction was run (out of scope for this tool). The vulnerability is demonstrated by static code inspection: `Erc20Credit(amount)` in `withdraw_asset_with_surplus` (erc20_transactor.rs:198-201) is constructed from the requested `amount` parameter, not from an observed balance delta on `TransfersCheckingAccount`, while `deposit_asset_with_surplus` (erc20_transactor.rs:253) subsequently attempts to move that same nominal `amount` out of the checking account. A minimal integration reproduction would: (1) deploy a fee-on-transfer ERC20 contract via `pallet-revive` on Asset Hub Westend, (2) register it as a fungible asset location matched by `ERC20Matcher`, (3) submit a signed `pallet_xcm::execute`/`transfer_assets` XCM program that withdraws and then deposits that asset, and (4) observe the deposit-side `IERC20.transfer` call fail/return `false` once the checking account's real balance falls short of the nominal `amount`, producing `XcmError::FailedToTransactAsset("ERC20 contract transfer failed")`. This reproduction was not executed against a live node/test harness in this analysis; it is presented as a code-level Medium-severity analog to the source finding, not a proven exploit run.

### Citations

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
