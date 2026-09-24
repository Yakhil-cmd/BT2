### Title
Fee-on-transfer/deflationary ERC20 tokens cause XCM holding to be credited more than actually escrowed in `ERC20Transactor`, enabling theft of other users' locked tokens - (File: `cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs`)

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` treat the `amount` requested in the XCM `Asset` as the amount actually moved by the underlying ERC20 `transfer()` call, only checking the boolean return value rather than the real balance delta. For fee-on-transfer/deflationary ERC20 tokens this mirrors the confirmed Gravity `sendToCosmos` bug: the XCM executor's `AssetsInHolding` is credited with the full requested `amount` even though the shared `ERC20TransfersCheckingAccount` escrow received less.

### Finding Description
`withdraw_asset_with_surplus` builds a `transferCall{to: checking_address, value: amount}` and, on `is_success == true`, unconditionally credits the holding register with the full `amount` via `AssetsInHolding::new_from_fungible_credit(what.id.clone(), Box::new(Erc20Credit(amount)))`: [1](#0-0) 

Symmetrically, `deposit_asset_with_surplus` transfers `amount` from the shared checking account to the beneficiary and treats a `true` return as fully successful, without verifying the beneficiary actually received `amount`: [2](#0-1) 

Standard ERC20 fee-on-transfer/deflationary tokens return `true` from `transfer()` while delivering `amount - fee` to the recipient — exactly the pattern the Gravity report flags. Because this transactor uses a *shared* escrow account (`ERC20TransfersCheckingAccount`, a fixed `PalletId(*b"py/revch")`-derived account used for every user and every ERC20 token routed through this transactor) rather than a per-asset/per-transfer balance, the accounting invariant "sum of holding credits == checking-account balance" is broken across users: [3](#0-2) 

`ERC20Matcher: MatchesFungibles<H160, u128>` maps an XCM `Asset`'s location/id directly to an arbitrary `H160` contract address, and `AssetTransactors` wires `ERC20Transactor` into the live `AssetHubWestend` XCM executor: [4](#0-3) 

Any unprivileged account can deploy a `pallet-revive` contract implementing a fee-on-transfer ERC20 (a permitted, non-privileged action), then execute a permissionless local XCM program (via `pallet_xcm::execute`, `ExecuteXcmOrigin = EnsureXcmOrigin<..., LocalOriginToLocation>`, `XcmExecuteFilter = Everything`) containing `WithdrawAsset` for that asset. Because `withdraw_asset_with_surplus` credits the full nominal `amount` into holding while the checking account actually received `amount - fee`, the attacker's holding balance is inflated relative to what is truly backed inside the shared checking account for that token.

### Impact Explanation
If the checking account also holds real balance deposited by other, honest users of the same ERC20 asset (any two users routing the same token through this transactor, e.g. two different XCM programs withdrawing/depositing the same fee-on-transfer token over time), an attacker can use the "phantom" surplus credited to their own holding to `DepositAsset` more tokens out of the shared checking account than they personally contributed — draining balance that rightfully belongs to other depositors, exactly the "steal tokens from user B" scenario Althea confirmed as High severity. This is a theft-of-funds class issue (unbacked/over-credited holding value) reachable purely by an unprivileged user deploying their own contract and issuing local XCM `execute`.

### Likelihood Explanation
Likelihood depends entirely on whether any fee-on-transfer/deflationary ERC20 contract is ever routed through `ERC20Transactor` with the shared checking account holding balances contributed by more than one party/token flow. `ERC20Matcher`'s exact contract-address <-> asset-id mapping and any additional admission/allow-list controls beyond `MatchesFungibles` could not be located within the available index in the time available, so it is **not confirmed** whether arbitrary, unregistered ERC20 contracts (including attacker-deployed ones) are actually reachable through this code path in production configuration, or whether some other gate (e.g., an asset registration process, or `pallet-revive` deployment restrictions on `AssetHubWestend`) reduces this to a config-only/privileged-prerequisite scenario. This uncertainty is why the finding is reported as a credible analog rather than a fully proven exploit chain.

### Recommendation
In both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, compute the actual amount moved by reading the ERC20 `balanceOf` of the checking account (or beneficiary) before and after the `transfer` call, and use that delta — not the nominal `amount` — both for the `AssetsInHolding` credit and for what is withdrawn from holding on deposit. Alternatively, reject/disallow assets whose `transfer()` behavior cannot be assumed to conserve `amount` (e.g., via a pre-flight self-test or an explicit allow-list of audited ERC20 contracts).

### Proof of Concept
No executable local Rust/FRAME or XCM integration reproduction was run; this submission is a static-analysis analog based on code inspection only. Guards checked and found insufficient: the code checks only the ERC20 boolean return value (`is_success`) and never re-reads on-chain balances to confirm the transferred amount matches `amount` (lines 166–216 and 218–306 of `erc20_transactor.rs`). What remains unverified: (1) the exact address-derivation logic inside `assets_common::ERC20Matcher` (not located in the index) that determines whether arbitrary/attacker-deployed contracts can be represented as XCM assets, and (2) whether `ERC20TransfersCheckingAccount` in practice ever aggregates deposits from more than one independent flow (a prerequisite for the cross-user theft impact). Because these two points could not be confirmed against the full source within the available tool budget, this should be treated as a plausible, testable hypothesis requiring a Devin/engineer follow-up with an integration test that (a) deploys a mock fee-on-transfer ERC20 via `pallet-revive`, (b) registers/matches it through `ERC20Matcher`, (c) executes `WithdrawAsset`/`DepositAsset` XCM programs from two distinct accounts, and (d) asserts whether the second account can withdraw more than it deposited.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L166-204)
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
				} else {
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L251-279)
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
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs (L213-246)
```rust
parameter_types! {
	/// Taken from the real gas and deposits of a standard ERC20 transfer call.
	pub const ERC20TransferGasLimit: Weight = Weight::from_parts(500_000_000_000, 10 * 1024 * 1024);
	pub const ERC20TransferStorageDepositLimit: Balance = 10_200_000_000;
	pub ERC20TransfersCheckingAccount: AccountId = PalletId(*b"py/revch").into_account_truncating();
	pub DapBufferAccount: AccountId = pallet_dap::Pallet::<Runtime>::buffer_account();
}

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
