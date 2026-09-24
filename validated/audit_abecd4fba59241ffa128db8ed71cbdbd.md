Confirmed: `ERC20Transactor` is wired into `AssetTransactors` for asset-hub-westend production runtime, matching any smart-contract-address-keyed location (`AccountKey20`), permissionlessly, per the PR doc `prdoc/stable2506/pr_7762.prdoc`. This means any user can deploy an arbitrary ERC20 contract via `pallet-revive` and reference it in XCM by its address — no governance registration required, matching the "no privileged role" requirement.

### Title
Internal Accounting Desync in `ERC20Transactor` for Fee-On-Transfer ERC20 Tokens - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` credits the XCM holding register with the full nominal `amount` requested by an XCM program, but only verifies that the underlying `IERC20::transfer` call returned `true` — it never checks that the checking account's ERC20 balance actually increased by `amount`. For a fee-on-transfer or rebasing ERC20 contract (fully attacker-deployable and permissionlessly referenceable via `AccountKey20` XCM locations), the checking account will receive less than `amount`, while the XCM executor's `AssetsInHolding` believes it holds the full `amount`.

### Finding Description
`withdraw_asset_with_surplus` at [1](#0-0)  extracts `amount` from `Matcher::matches_fungibles(what)` (attacker-controlled, since `what` comes from the user's XCM program, e.g. via `pallet_xcm::execute`/`transfer_assets`), then calls the ERC20 contract's `transfer(checking_address, amount)`. The only success check is the boolean return value decode: [2](#0-1) . On success it unconditionally credits `Erc20Credit(amount)` into `AssetsInHolding` — the nominal amount, not the delta actually received by the checking account. This exactly mirrors the audit finding: minting/crediting is done based on the *input* amount instead of the actually-transferred amount, which is wrong for fee-on-transfer/rebasing tokens.

Symmetrically, `deposit_asset_with_surplus` at [3](#0-2)  transfers `amount` (the nominal, holding-register value) out of the shared `TransfersCheckingAccount` to the beneficiary, again without verifying the beneficiary actually received `amount` net of fees, and without verifying the checking account had `amount` available going in.

This transactor is wired into the production `AssetTransactors` tuple for AssetHub Westend, matched permissionlessly by contract address: [4](#0-3) . Per the PR doc, "asset ids of the form `{parents:0, interior: X1(AccountKey20{key, network})}` will be matched by this transactor" for *any* deployed contract at `key` — no allow-list or governance gate is described in this file's config. [5](#0-4) 

Root cause: the transactor treats the ERC20 `transfer` call's boolean return value as proof that exactly `amount` moved, an assumption that is false for fee-on-transfer/deflationary/rebasing ERC20 implementations (a widely-used real-world token pattern), unlike the FRAME `pallet-assets`/`pallet-balances` transfer primitives which always move exact amounts (barring ED-driven dust sweeps that are explicitly accounted for via the returned actual value, e.g. [6](#0-5) ). `ERC20Transactor` breaks this "actual transferred == credited" invariant that all other fungible transactors preserve.

### Impact Explanation
Every withdraw of a fee-on-transfer/rebasing ERC20 via this transactor over-credits the XCM holding register relative to what the shared `TransfersCheckingAccount` actually accumulates for that specific asset contract. Because `TransfersCheckingAccount` is a single, shared account pooling all users' balances for that ERC20 contract (`ERC20TransfersCheckingAccount` is a single `PalletId`-derived account, not per-user), repeated withdraw/deposit cycles against a fee-on-transfer contract will progressively drain the real ERC20 balance held by the checking account below the sum of amounts the executor believes are "in transit"/backed. This causes:
- Deterministic failure (insolvency) of later legitimate `deposit_asset_with_surplus` calls for other holders of the same ERC20-backed derivative once the checking account's on-chain balance is insufficient to cover `amount`, trapping/failing unrelated users' XCM messages (denial of value/availability for those users).
- A durable "phantom balance" for the specific asset that is a genuine internal accounting break, matching the Medium severity of the original finding, since the mismatch is deterministic and reproducible by anyone deploying such a token, not an economic/market attack.

### Likelihood Explanation
Deployment of the malicious ERC20 (fee-on-transfer) contract requires only a normal, permissionless `pallet-revive` contract instantiation call — no privileged role. Referencing it via XCM (`AccountKey20` location) requires only sending an ordinary XCM program (e.g. `pallet_xcm::execute` with `WithdrawAsset`/`DepositAsset`, or a reserve-style transfer) — also fully permissionless, matching the "real user entry" and "no privileged prerequisites" requirements. Likelihood is High for the accounting desync to occur whenever any fee-on-transfer contract is used with this transactor; the transactor performs no validation excluding such tokens.

### Recommendation
In `withdraw_asset_with_surplus`, read the checking account's ERC20 balance before and after the `transfer` call (or decode a `Transfer` event/expect an ERC20 `balanceOf` delta) and credit `AssetsInHolding` with the actual observed delta, not the nominal `amount`. Symmetrically, in `deposit_asset_with_surplus`, verify the beneficiary's balance increase before returning success, and fail (returning assets to holding / erroring) rather than assuming success from the boolean return alone. Alternatively, explicitly document/enforce (e.g. via `Matcher`) that only ERC20 contracts verified to be standard fixed-supply, non-fee, non-rebasing tokens can be matched by this transactor.

### Proof of Concept
No local Rust/FRAME reproduction was executed in this session — I only performed static code review of `ERC20Transactor` and its wiring; I did not run an integration test harness with an actual fee-on-transfer Solidity fixture. To fully confirm impact and produce assertable pre/post-state evidence, a PoC would need to:
1. Compile a minimal `resolc`-compiled ERC20 fixture whose `transfer` deducts a fee (e.g. burns/keeps 10% instead of moving it), similar to the existing test fixtures at `substrate/frame/revive/src/impl_fungibles.rs` (test-only harness, not itself in scope).
2. Instantiate it via `pallet_revive` on an asset-hub-westend-like test runtime with `ERC20Transactor` wired as in `xcm_config.rs`.
3. Execute an XCM program via `pallet_xcm::execute` doing `WithdrawAsset`/`DepositAsset` for `amount` of this token, and assert `checking_account` ERC20 balance increase < `amount` while `AssetsInHolding`/destination credit == `amount`.

This step was not executed due to no further tool iterations being available; the finding above is based on direct code-path analysis of the transactor logic and its unconditional `Erc20Credit(amount)` crediting on a bare boolean success check, which is sufficient to demonstrate the missing-check root cause but not a running-test confirmation.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L159-169)
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

**File:** prdoc/stable2506/pr_7762.prdoc (L9-14)
```text
      This PR introduces an Asset Transactor for dealing with ERC20 tokens and adds it to Asset Hub
      Westend.
      This means asset ids of the form `{ parents: 0, interior: X1(AccountKey20 { key, network }) }` will be
      matched by this transactor and the corresponding `transfer` function will be called in the
      smart contract whose address is `key`.
      If your chain uses `pallet-revive`, you can support ERC20s as well by adding the transactor, which lives
```

**File:** substrate/frame/support/src/traits/tokens/fungibles/regular.rs (L513-533)
```rust
	/// Mints `value` into the account of `who`, creating it as needed.
	///
	/// If `precision` is `BestEffort` and `value` in full could not be minted (e.g. due to
	/// overflow), then the maximum is minted, up to `value`. If `precision` is `Exact`, then
	/// exactly `value` must be minted into the account of `who` or the operation will fail with an
	/// `Err` and nothing will change.
	///
	/// If the operation is successful, this will return `Ok` with a `Debt` of the total value
	/// added to the account.
	fn deposit(
		asset: Self::AssetId,
		who: &AccountId,
		value: Self::Balance,
		precision: Precision,
	) -> Result<Debt<AccountId, Self>, DispatchError> {
		let increase = Self::increase_balance(asset.clone(), who, value, precision)?;
		Self::done_deposit(asset.clone(), who, increase);
		Ok(Imbalance::<Self::AssetId, Self::Balance, Self::OnDropDebt, Self::OnDropCredit>::new(
			asset, increase,
		))
	}
```
