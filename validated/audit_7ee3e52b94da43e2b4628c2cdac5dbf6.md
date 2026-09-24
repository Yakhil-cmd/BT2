Confirmed: `ERC20Matcher` matches on `IsLocalAccountKey20` — any location of the form `(0, [AccountKey20 { .. }])` — meaning **any contract address**, including one deployed permissionlessly by an attacker via `pallet-revive`, is accepted as a valid "asset" for the `ERC20Transactor`. This makes the transactor genuinely attacker-reachable with a hostile ERC20 implementation.

### Title
XCM `ERC20Transactor` trusts the nominal transfer `amount` for fee-on-transfer/deflationary ERC20 tokens instead of the actual balance delta, permanently trapping user funds - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` call an arbitrary ERC20 contract's `transfer()` and, on a `true` return, unconditionally credit/debit the **nominal `amount`** requested in the XCM `Asset`, never checking the actual balance change of the `TransfersCheckingAccount`. Since `ERC20Matcher` (`IsLocalAccountKey20`) accepts any `AccountKey20` location, an attacker can permissionlessly deploy a fee-on-transfer ERC20 via `pallet-revive` and drive this code path with a token that silently deducts a fee on `transfer()`.

### Finding Description [1](#0-0) 
In `withdraw_asset_with_surplus`, the transactor calls the ERC20's `transferCall{to: checking_address, value: amount}` and, if the call succeeds and returns `true`, blindly constructs `AssetsInHolding::new_from_fungible_credit(what.id, Erc20Credit(amount))` — crediting the *nominal* `amount` into the XCM holding register regardless of what the checking account actually received. [2](#0-1) 
The `Erc20Credit` type is explicitly documented as *not* performing runtime-level balance enforcement — "the actual balance constraints are enforced by the ERC20 smart contract itself" — an assumption that only holds for well-behaved, non-fee-on-transfer, non-rebasing tokens. [3](#0-2) 
`ERC20Matcher` (`IsLocalAccountKey20` + `AccountKey20ToH160`) matches **any** local `AccountKey20` location as a valid ERC20 asset — there is no allowlist. Any user can deploy an arbitrary Solidity contract through `pallet-revive` (a normal, permissionless, permitted user action) and immediately use it in XCM programs executed via `pallet_xcm::execute`/`send`, exactly like the `withdraw_and_deposit_erc20s` test demonstrates end-to-end. [4](#0-3) 

If the attacker's ERC20 implements a fee-on-transfer (e.g., burns/redirects a percentage on every `transfer`), then:
1. `WithdrawAsset` for `amount = X` moves `X` out of the attacker's own balance but the checking account actually receives `X - fee`.
2. The XCM holding register nevertheless records a credit of `X` (not `X - fee`).
3. When the program proceeds to `DepositAsset` for the full `X` to a beneficiary, `deposit_asset_with_surplus` (lines 251-266) attempts `transferCall{to: beneficiary, value: X}` from the checking account, but the checking account's real balance is only `X - fee` — the standard ERC20 `_update` balance check (`fromBalance < value` revert) causes the contract call to fail. [5](#0-4) 
4. `deposit_asset_with_surplus` then returns `Err((what, XcmError::FailedToTransactAsset(...)))` with `what` still carrying the *nominal* (unbacked) amount `X`. [6](#0-5) 

Per standard XCM executor semantics, a failed `DepositAsset` traps the held assets (`AssetTrap`) at the nominal amount `X`, recorded against the origin/ticket. But the `TransfersCheckingAccount`'s real, on-chain ERC20 balance backing that trap is only `X - fee` — permanently less than what was recorded as trapped. Any subsequent `ClaimAsset`/`DepositAsset` attempt to redeem the trap for the full `X` will fail identically, because the checking account can never actually hold `X` (the fee was irrecoverably burned/redirected by the token contract on the very first `transfer`). This breaks the invariant that "assets recorded in XCM holding/traps are fully backed by the real balance of the account acting as their custodian" — the same invariant violated in the original Allo.sol report, where the protocol assumed `_transferAmountFrom` always delivers the exact nominal amount.

### Impact Explanation
User funds routed through this transactor with a fee-on-transfer token become permanently unrecoverable: the fee portion is burned by the token contract, and the remainder is stuck because the trap/claim accounting always requires the full nominal amount that the checking account can never actually hold again. This is a loss-of-funds bug for any user (self-inflicted since they choose the token, but also affects any third party relying on that ERC20 for legitimate reserve/local transfers through this transactor) and represents a genuine violation of the "amount transacted equals amount recorded" invariant central to the reported fee-on-transfer bug class. Because `ERC20Transactor` is wired directly into `AssetTransactors` for asset-hub-westend, this is live production configuration, not test-only code. [7](#0-6) 

### Likelihood Explanation
Deploying a custom ERC20 via `pallet-revive` and executing an XCM program via `pallet_xcm::execute` are both ordinary, permissionless, currently-enabled user actions requiring no privileged role — matching the required "real user entry" criterion. The `ERC20Matcher` places no restriction preventing arbitrary/attacker-deployed contracts from being used, so reachability is straightforward. However, since the attacker must supply their own malicious token, this mainly harms that user (self-inflicted loss) and third parties who are induced to accept the same token as a means of value transfer; it does not directly enable theft of unrelated, honest-token balances. This bounds it to a Medium-severity finding, consistent with the analogous accepted Medium in the original report.

### Recommendation
Do not trust the nominal `amount`/ERC20 return value alone. In both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, read the `TransfersCheckingAccount`'s (or beneficiary's) actual ERC20 balance before and after the `bare_call`, and use the observed delta as the amount credited/debited into `AssetsInHolding` and as the value considered "backed." Reject or partially credit transfers where the delta does not match the requested nominal amount, rather than assuming ERC20 contracts always move exactly the requested value.

### Proof of Concept
Not independently executed in this session (no filesystem/terminal access available to me); this analysis is based on static code review of `erc20_transactor.rs`, `ERC20Matcher`, and the existing `withdraw_and_deposit_erc20s` integration test that already exercises this exact call path end-to-end (deploy contract via `pallet-revive`, `withdraw_asset`/`deposit_asset` via `PolkadotXcm::execute`). [8](#0-7) 
A concrete reproduction would extend that test with a fee-on-transfer variant of the `MyToken` fixture (deduct e.g. 10% on every `_update`/`transfer`) and assert that after `withdraw_asset` + `deposit_asset`, the `DepositAsset` step errors with `FailedToTransactAsset` while the XCM `AssetTrap` event reports the pre-fee nominal amount — demonstrating the checking account can never fully back the trapped amount. I was not able to run this reproduction; a Devin session with Rust toolchain access would be required to compile and execute it against the `asset-hub-westend` test runtime.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L73-107)
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

impl UnsafeManualAccounting<u128> for Erc20Credit {
	fn saturating_subsume(&mut self, mut other: Box<dyn ImbalanceAccounting<u128>>) {
		let amount = other.forget_imbalance();
		self.0 = self.0.saturating_add(amount);
	}
}

impl ImbalanceAccounting<u128> for Erc20Credit {
	fn amount(&self) -> u128 {
		self.0
	}
	fn saturating_take(&mut self, amount: u128) -> Box<dyn ImbalanceAccounting<u128>> {
		let new = self.0.min(amount);
		self.0 = self.0 - new;
		Box::new(Erc20Credit(new))
	}
}
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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L270-286)
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
```

**File:** cumulus/parachains/runtimes/assets/common/src/lib.rs (L157-160)
```rust
/// [`xcm_executor::traits::MatchesFungibles`] implementation that matches
/// ERC20 tokens.
pub type ERC20Matcher =
	MatchedConvertedConcreteId<H160, u128, IsLocalAccountKey20, AccountKey20ToH160, TryConvertInto>;
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L1871-1936)
```rust
#[test]
fn withdraw_and_deposit_erc20s() {
	let sender: AccountId = ALICE.into();
	let beneficiary: AccountId = BOB.into();
	let revive_account = pallet_revive::Pallet::<Runtime>::account_id();
	let checking_account =
		asset_hub_westend_runtime::xcm_config::ERC20TransfersCheckingAccount::get();
	let initial_wnd_amount = 100_000_000_000_000_000u128;
	sp_tracing::init_for_tests();

	ExtBuilder::<Runtime>::default().build().execute_with(|| {
		// Bring the revive account to life.
		assert_ok!(Balances::mint_into(&revive_account, initial_wnd_amount));
		// Fund all accounts involved.
		assert_ok!(Balances::mint_into(&sender, initial_wnd_amount));
		assert_ok!(Balances::mint_into(&beneficiary, initial_wnd_amount));
		assert_ok!(Balances::mint_into(&checking_account, initial_wnd_amount));

		let code = compile_module_with_type("MyToken", FixtureType::Resolc)
			.expect("compile ERC20")
			.0;

		let initial_amount_u256 = U256::from(1_000_000_000_000u128);
		let constructor_data = sol_data::Uint::<256>::abi_encode(&initial_amount_u256);
		let Contract { addr: erc20_address, .. } = bare_instantiate(&sender, code)
			.transaction_limits(TransactionLimits::WeightAndDeposit {
				weight_limit: Weight::from_parts(500_000_000_000, 10 * 1024 * 1024),
				deposit_limit: Balance::MAX,
			})
			.data(constructor_data)
			.build_and_unwrap_contract();

		let sender_balance_before = <Balances as fungible::Inspect<_>>::balance(&sender);

		let erc20_transfer_amount = 100u128;
		let wnd_amount_for_fees = 10_000_000_000_000u128;
		// Actual XCM to execute locally.
		let message = Xcm::<RuntimeCall>::builder()
			.withdraw_asset((Parent, wnd_amount_for_fees))
			.pay_fees((Parent, wnd_amount_for_fees))
			.withdraw_asset((
				AccountKey20 { key: erc20_address.into(), network: None },
				erc20_transfer_amount,
			))
			.deposit_asset(AllCounted(1), beneficiary.clone())
			.refund_surplus()
			.deposit_asset(AllCounted(1), sender.clone())
			.build();
		assert_ok!(PolkadotXcm::execute(
			RuntimeOrigin::signed(sender.clone()),
			Box::new(VersionedXcm::V5(message)),
			Weight::from_parts(600_000_000_000, 15 * 1024 * 1024),
		));

		// Revive is not taking any fees.
		let sender_balance_after = <Balances as fungible::Inspect<_>>::balance(&sender);
		// Balance after is larger than the difference between balance before and transferred
		// amount because of the refund.
		assert!(sender_balance_after > sender_balance_before - wnd_amount_for_fees);

		// Beneficiary receives the ERC20.
		let beneficiary_amount =
			<Revive as fungibles::Inspect<_>>::balance(erc20_address, &beneficiary);
		assert_eq!(beneficiary_amount, erc20_transfer_amount);
	});
}
```

**File:** substrate/frame/revive/fixtures/contracts/external/openzeppelin/contracts/token/ERC20/ERC20.sol (L176-189)
```text
    function _update(address from, address to, uint256 value) internal virtual {
        if (from == address(0)) {
            // Overflow check required: The rest of the code assumes that totalSupply never overflows
            _totalSupply += value;
        } else {
            uint256 fromBalance = _balances[from];
            if (fromBalance < value) {
                revert ERC20InsufficientBalance(from, fromBalance, value);
            }
            unchecked {
                // Overflow not possible: value <= fromBalance <= totalSupply.
                _balances[from] = fromBalance - value;
            }
        }
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
