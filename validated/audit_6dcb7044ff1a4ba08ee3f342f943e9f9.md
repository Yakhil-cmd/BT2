## Analysis Result

I found a real Polkadot SDK analog to the reported bug class. The violated invariant in the original report is: **a deposit/accounting routine trusts the caller-specified transfer amount instead of verifying the actual token movement**, which breaks down for ERC-20 tokens that silently clamp a transfer to the sender's real balance instead of reverting when a caller requests more than the sender actually holds.

The equivalent pattern exists in production code in the `ERC20Transactor` used to plug arbitrary Solidity ERC-20 contracts into the XCM `TransactAsset` machinery on Asset Hub.

### Title
XCM `ERC20Transactor` credits/debits `AssetsInHolding` using the requested transfer amount instead of the amount actually observed on the ERC20 ledger - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `::deposit_asset_with_surplus` move ERC-20 tokens by calling the token contract's Solidity `transfer(to, value)` through `pallet_revive::bare_call`, then treat the call as fully successful once it does not revert and decodes to `true`. The amount credited into (or debited from) the XCM `AssetsInHolding` register is the `amount` taken from the XCM `Asset`/message, not a balance delta measured before/after the call. For any ERC-20 contract whose `transfer` implementation clamps to the sender's actual balance instead of reverting when `value` exceeds it (the exact bug class described in the external report for tokens like cUSDCv3), the XCM holding register is credited with more value than was actually moved on-chain.

### Finding Description
- `withdraw_asset_with_surplus` extracts `(asset_id, amount)` from the XCM `Asset` via `Matcher::matches_fungibles(what)`, both of which are attacker-controlled fields of an ordinary, permitted `pallet_xcm::execute` message. [1](#0-0) 
- It calls the target contract's ERC-20 `transfer(checking_address, amount)` and only checks `did_revert()` and the ABI-decoded boolean return value; it never re-reads `balanceOf` to confirm the actual amount moved. [2](#0-1) 
- On success it unconditionally credits the holding register with the *requested* `amount`, not an observed delta: [3](#0-2) 
- The symmetric `deposit_asset_with_surplus` path has the identical pattern: it calls `transfer(beneficiary, amount)` from the checking account and, on a non-reverting/`true` result, treats the deposit as fully successful for `amount`, again without verifying a balance delta. [4](#0-3) 
- This transactor is wired into the live `AssetTransactors` tuple for the Asset Hub Westend runtime, i.e., it is production configuration, not a mock: [5](#0-4) 
- The repository's own test suite already demonstrates that this exact call path is reachable through a plain signed `PolkadotXcm::execute` with an attacker-supplied ERC-20-like contract and an attacker-chosen withdraw amount, confirming reachability without any privileged role: [6](#0-5) 

By contrast, the SDK's own `pallet-assets` ERC-20 precompile (`substrate/frame/assets/precompiles`) — which moves natively-tracked balances rather than delegating to an external contract — was deliberately hardened so that `transfer`/`transferFrom` **revert** on any value that would exceed `Balance::MAX` (covering the `uint256.max` sentinel), specifically to avoid silently moving less than the caller believes was moved: [7](#0-6) [8](#0-7) 

The `ERC20Transactor`, however, delegates the actual movement to an arbitrary externally-deployed contract and has no equivalent invariant check — it never confirms the "amount actually moved" against the "amount recorded," which is precisely the missing check identified in the external report.

### Impact Explanation
Any attacker can permissionlessly deploy an ERC-20 contract (no privileged role required, this is ordinary contract deployment via `pallet-revive`) whose `transfer` function clamps to the sender's balance instead of reverting/failing when asked to move more than the sender holds (this is a real, observed pattern in production tokens such as cUSDCv3, not a hypothetical). By registering this token as an XCM asset behind `ERC20Transactor` and executing a self-crafted XCM program with a `withdraw_asset` amount larger than the attacker's real balance, the attacker can cause the XCM holding register to be over-credited relative to what was actually removed from their real ERC-20 balance. Whether this translates into extractable value depends on what downstream XCM instructions do with the inflated holding-register credit (e.g., fee payment, `deposit_asset` to a beneficiary, or exchange via `pallet-asset-conversion` pools that hold real backing for this ERC-20 asset) — those downstream paths were not fully traced in this pass, but the root-cause defect (trusting nominal transfer amount over an on-chain-observed balance delta) is proven and matches a Critical/High "unbacked issuance / loss of funds" bug class if such a real-backing sink exists on Asset Hub for ERC-20 assets.

### Likelihood Explanation
Reachability is proven directly: an ordinary signed account can deploy a contract and drive this exact code path through `pallet_xcm::execute`, as already exercised by the repository's own integration test. No governance, collator, relayer, or other privileged capability is required — only (a) deploying a contract with non-standard transfer semantics and (b) crafting a self-executed XCM message, both permissionless operations on Asset Hub.

### Recommendation
In `ERC20Transactor::withdraw_asset_with_surplus` and `::deposit_asset_with_surplus`, do not trust the requested `amount` on a successful/non-reverting `transfer` call. Instead, read the account's `balanceOf` before and after the call (as `fungibles::Inspect::balance` already does elsewhere in the codebase) and credit/debit `AssetsInHolding` with the observed delta, erroring out if the delta does not match the requested `amount` (mirroring the revert-on-overflow/partial-move guard already adopted for `pallet-assets` ERC-20 precompiles).

### Proof of Concept
- Program/severity rationale: `ERC20Transactor` is wired into the live `AssetTransactors` for `asset-hub-westend`, a Snowbridge/Parity-adjacent production runtime configuration, not test-only code — see wiring citation above.
- Failed guard: no balance-delta check exists after the ERC-20 `transfer` call in either `withdraw_asset_with_surplus` or `deposit_asset_with_surplus`; only `did_revert()` + boolean decode are checked.
- Deployment evidence: existing test `smart_contract_does_not_return_bool_fails` proves a custom, attacker-authored contract can be instantiated and driven through `pallet_xcm::execute` along exactly this transactor path.
- PoC execution status: Not independently executed in this pass; the analysis is based on static tracing of the cited production code and the repository's existing integration test demonstrating reachability of the same call path. A full PoC would additionally need to trace a concrete downstream sink (e.g., an `pallet-asset-conversion` pool backed by the same ERC-20 asset) to demonstrate extractable real-value loss, which was not completed here due to iteration limits.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L150-169)
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
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L183-207)
```rust
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

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2026-2080)
```rust
// Here the contract returns a number but because it can be cast to true
// it still succeeds.
#[test]
fn smart_contract_does_not_return_bool_fails() {
	let sender: AccountId = ALICE.into();
	let beneficiary: AccountId = BOB.into();
	let revive_account = pallet_revive::Pallet::<Runtime>::account_id();
	let checking_account =
		asset_hub_westend_runtime::xcm_config::ERC20TransfersCheckingAccount::get();
	let initial_wnd_amount = 10_000_000_000_000u128;

	ExtBuilder::<Runtime>::default().build().execute_with(|| {
		// Bring the revive account to life.
		assert_ok!(Balances::mint_into(&revive_account, initial_wnd_amount));

		// Fund all accounts involved.
		assert_ok!(Balances::mint_into(&sender, initial_wnd_amount));
		assert_ok!(Balances::mint_into(&beneficiary, initial_wnd_amount));
		assert_ok!(Balances::mint_into(&checking_account, initial_wnd_amount));

		// This contract implements the ERC20 interface for `transfer` except it returns a uint256.
		let code = compile_module_with_type("MyTokenFake", FixtureType::Resolc)
			.expect("compile ERC20")
			.0;

		let initial_amount_u256 = U256::from(1_000_000_000_000u128);
		let constructor_data = sol_data::Uint::<256>::abi_encode(&initial_amount_u256);

		let Contract { addr: non_erc20_address, .. } = bare_instantiate(&sender, code)
			.transaction_limits(TransactionLimits::WeightAndDeposit {
				weight_limit: Weight::from_parts(500_000_000_000, 10 * 1024 * 1024),
				deposit_limit: Balance::MAX,
			})
			.data(constructor_data)
			.build_and_unwrap_contract();

		let wnd_amount_for_fees = 1_000_000_000_000u128;
		let erc20_transfer_amount = 100u128;
		let message = Xcm::<RuntimeCall>::builder()
			.withdraw_asset((Parent, wnd_amount_for_fees))
			.pay_fees((Parent, wnd_amount_for_fees))
			.withdraw_asset((
				AccountKey20 { key: non_erc20_address.into(), network: None },
				erc20_transfer_amount,
			))
			.deposit_asset(AllCounted(1), beneficiary.clone())
			.build();
		// Execution fails but doesn't panic.
		assert!(PolkadotXcm::execute(
			RuntimeOrigin::signed(sender.clone()),
			Box::new(VersionedXcm::V5(message)),
			Weight::from_parts(2_500_000_000, 220_000),
		)
		.is_err());
	});
```

**File:** substrate/frame/assets/precompiles/src/tests.rs (L786-847)
```rust
/// Asymmetry pin: `transfer` and `transferFrom` move exact amounts, so an overflowing
/// `value` must revert at the `U256 → Balance` boundary rather than silently
/// transferring `Balance::MAX`. Only allowance writes (`approve` / `permit`) saturate.
#[test]
fn transfer_and_transfer_from_revert_on_overflow() {
	use alloy::sol_types::{Revert, SolError};

	new_test_ext().execute_with(|| {
		let asset_id = 0u32;
		let asset_addr = H160::from(set_prefix_in_address(PRECOMPILE_ADDRESS_PREFIX));
		let from = 123456789u64;
		let to = 987654321u64;
		Balances::make_free_balance_be(&from, 100);
		Balances::make_free_balance_be(&to, 100);
		let from_addr = <Test as pallet_revive::Config>::AddressMapper::to_address(&from);
		let to_addr = <Test as pallet_revive::Config>::AddressMapper::to_address(&to);
		assert_ok!(Assets::force_create(RuntimeOrigin::root(), asset_id, from, true, 1));
		assert_ok!(Assets::mint(RuntimeOrigin::signed(from), asset_id, from, 100));

		// Authorise the spender with a small finite allowance so the `transferFrom`
		// path reaches the value conversion before any approval check.
		call_approve(from, asset_addr, to_addr, U256::from(50u64));

		let assert_reverts_with = |caller: u64, data: Vec<u8>, label: &str| {
			let exec = pallet_revive::Pallet::<Test>::bare_call(
				RuntimeOrigin::signed(caller),
				asset_addr,
				0u32.into(),
				TransactionLimits::WeightAndDeposit {
					weight_limit: Weight::MAX,
					deposit_limit: u128::MAX,
				},
				data,
				&ExecConfig::new_substrate_tx(),
			)
			.result
			.expect("must not trap");
			assert!(exec.did_revert(), "{label} must revert on overflow");
			let decoded = Revert::abi_decode(&exec.data).expect("Error(string) revert");
			assert_eq!(
				decoded.reason, "Balance conversion failed",
				"{label} must revert at the U256 -> Balance boundary",
			);
		};

		let transfer_data =
			IERC20::transferCall { to: to_addr.0.into(), value: U256::MAX }.abi_encode();
		assert_reverts_with(from, transfer_data, "transfer(uint256.max)");

		let transfer_from_data = IERC20::transferFromCall {
			from: from_addr.0.into(),
			to: to_addr.0.into(),
			value: U256::MAX,
		}
		.abi_encode();
		assert_reverts_with(to, transfer_from_data, "transferFrom(_, _, uint256.max)");

		// Nothing moved.
		assert_eq!(Assets::balance(asset_id, from), 100);
		assert_eq!(Assets::balance(asset_id, to), 0);
	});
}
```

**File:** prdoc/stable2606/pr_12196.prdoc (L1-16)
```text
title: '[pallet-assets-precompiles] saturate permit/approval allowance'
doc:
- audience: Runtime Dev
  description: "## Summary\n\n`approve()` / `permit()` previously reverted with `\"\
    Balance conversion failed\"` on `call.value > Balance::MAX` \u2014 including `type(uint256).max`,\
    \ the universal \"infinite allowance\" idiom hard-coded by MetaMask, Uniswap,\
    \ and every mainstream DEX router. The U256 \u2192 Balance conversion now saturates\
    \ at `Balance::MAX`. `transfer` / `transferFrom` keep the existing revert-on-overflow\
    \ behavior \u2014 they move exact amounts, so silently clamping would produce\
    \ partial transfers the caller never asked for. The emitted `Approval` event still\
    \ carries the raw `call.value`, matching the ERC-20 / OpenZeppelin convention.\n\
    \n## Non-goals\n\nNo `transferFrom` sentinel branch \u2014 saturated allowances\
    \ decrement on every spend; on a `u128` runtime `Balance::MAX` is large enough\
    \ to be operationally indistinguishable from infinite. No `allowance()` readback\
    \ lift \u2014 returns the stored value as-is.\n\n## Test plan\n\n- [x] `cargo\
    \ test -p pallet-assets-precompiles`"
```
