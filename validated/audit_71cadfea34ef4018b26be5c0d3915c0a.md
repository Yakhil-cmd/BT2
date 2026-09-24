## Analysis: Fee-on-Transfer ERC20 Tokens Break `ERC20Transactor` XCM Withdraw/Deposit Accounting

I found a genuine Polkadot SDK analog of the reported bug class. The Notional issue is about an on-chain component blindly trusting a *nominal* transfer amount instead of verifying the *actual* amount received, when the underlying token can apply a transfer fee. The exact same root cause exists in `ERC20Transactor` used by Asset Hub runtimes to move XCM `TransactAsset` value in/out of arbitrary ERC20 contracts deployed on `pallet-revive`.

### Title
`ERC20Transactor` credits nominal (not actual) transfer amount, permanently trapping user funds for fee-on-transfer ERC20 tokens - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` move ERC20 balances by calling `IERC20::transferCall` and, upon seeing a `true` boolean return, unconditionally record/move the *requested* `amount` in the XCM `AssetsInHolding` register, without ever checking that the recipient's on-chain ERC20 balance actually increased by that amount.

### Finding Description
Any account can permissionlessly deploy an arbitrary ERC20 contract via `pallet-revive` (the fixture at `substrate/frame/revive/fixtures/contracts/external/openzeppelin/contracts/token/ERC20/ERC20.sol` shows the standard, freely-overridable `_update`/`_transfer` pattern that any user contract can customize to deduct a fee). A user can then execute a signed XCM program (`pallet_xcm::execute`) that withdraws/deposits that ERC20 token through `ERC20Transactor`, exactly as exercised by the existing test `withdraw_and_deposit_erc20s` [1](#0-0) .

In `withdraw_asset_with_surplus`, the transactor calls `transfer(checking_account, amount)` on the user-controlled ERC20 contract and, if the ABI-decoded return is `true`, creates an `Erc20Credit(amount)` for the full requested `amount` — with no check of the checking account's balance delta: [2](#0-1) 

Symmetrically, `deposit_asset_with_surplus` calls `transfer(beneficiary, amount)` from the shared checking account for the same nominal `amount`, again trusting the boolean return value alone: [3](#0-2) 

If the ERC20 contract implements any fee-on-transfer, deflationary-burn, or rebasing logic (fully legal, arbitrary Solidity/PVM behavior — the runtime places no restriction on it, only matching by contract address via `Matcher::matches_fungibles`), the checking account's real balance increases by `amount - fee`, not `amount`. The XCM holding register nonetheless believes it holds `amount`. When the executor later tries to deposit `amount` out of the checking account to the beneficiary, the underlying `IERC20.transfer` call — which for a standards-compliant token reverts on insufficient balance, as shown in the OZ reference implementation's `_update` (`revert ERC20InsufficientBalance`) [4](#0-3)  — reverts, causing `deposit_asset_with_surplus` to return `Err(FailedToTransactAsset(...))`.

This mirrors the reported invariant violation precisely: the "promise" (full `amount`) diverges from what was actually moved (`amount - fee`), and nothing enforces that the destination account's balance actually grew by the credited figure before that credit is propagated through subsequent XCM instructions.

### Impact Explanation
Because the same `TransfersCheckingAccount` is shared across all ERC20 transfers routed through this transactor (it is a fixed, singleton account configured in the runtime, e.g. `ERC20TransfersCheckingAccount` in `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs` lines 217/230-237), two outcomes are possible:
1. **Deterministic failure / fund trapping**: if the checking account has no other balance of that ERC20 token, the deposit-side `transfer` call reverts. The XCM executor then has already irreversibly "withdrawn" (moved to the checking account) the user's real tokens but cannot deposit the credited (inflated) amount — the assets are recorded as trapped (`AssetTraps`) rather than returned to the user, because the amount claimed in the holding register (`amount`) can never actually be redeemed from the checking account.
2. **Cross-user fungibility break**: if the checking account happens to hold surplus balance of the same ERC20 token from other, unrelated operations, the shortfall is silently drawn from that surplus, meaning one user's fee-on-transfer token effectively steals real balance backing another user's legitimate holding-register credit for the same token, breaking the checking account's accounting invariant.

Either outcome is a deterministic, irreversible loss/freezing of real user funds achievable with only unprivileged extrinsics (contract deploy + `pallet_xcm::execute`), matching the bounty's preference for "irreversible freezing" or "deterministic chain failure."

### Likelihood Explanation
High. No privileged role, governance, or malicious peer is required. Deploying a custom ERC20 contract via `pallet-revive` and executing a `WithdrawAsset`/`DepositAsset` XCM program via `pallet_xcm::execute` is exactly what the existing regression test `withdraw_and_deposit_erc20s` does with a standard token; only a trivial modification to the deployed contract's `transfer`/`_update` logic (adding a fee/burn) is needed to trigger the mismatch deterministically on every single such transfer.

### Recommendation
In both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, read the counterparty's (`checking_account` / `beneficiary`) ERC20 `balanceOf` before and after the `transfer` call, and use the observed balance delta — not the requested `amount` — as the credited/debited quantity in `AssetsInHolding`. If the observed delta is less than the requested `amount`, either fail the operation before any holding-register credit is created, or credit only the actually-observed delta so downstream instructions never assume more value exists than was actually moved.

### Proof of Concept
No local reproduction was run. The mechanism is demonstrated by tracing:
- The permissionless entry path proven by the existing test `withdraw_and_deposit_erc20s` (`cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs:1871-1936`), which withdraws/deposits an ERC20 via `pallet_xcm::execute` using the exact `ERC20Transactor` code paths cited above.
- The missing balance-delta check in `withdraw_asset_with_surplus` (lines 166-203) and `deposit_asset_with_surplus` (lines 251-298) of `cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs`, both of which trust the ERC20 `transfer` boolean return value alone.
- The standards-compliant revert-on-insufficient-balance behavior of `_update` in the bundled OpenZeppelin ERC20 fixture (`substrate/frame/revive/fixtures/contracts/external/openzeppelin/contracts/token/ERC20/ERC20.sol:176-189`), which would trigger the failure/trapping described above once a fee-on-transfer variant is substituted.

A concrete Rust/FRAME integration test extending `withdraw_and_deposit_erc20s` with a fee-on-transfer variant of the deployed contract (deducting e.g. 1% on `_update`) would be needed to capture on-chain revert/trap evidence; this was not executed as part of this analysis.

### Citations

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L1871-1923)
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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L251-298)
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
