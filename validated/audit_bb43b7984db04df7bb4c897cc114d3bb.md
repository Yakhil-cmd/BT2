## Analog Found: XCM `ERC20Transactor` credits/debits the *requested* amount rather than the actual ERC20 balance change, unlike fee/rebase‑aware transfers elsewhere in the codebase

### Title
XCM `ERC20Transactor` assumes ERC20 `transfer()` moves exactly the requested amount, breaking accounting for fee-on-transfer/deflationary ERC20 tokens - (File: `cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs`)

### Summary
The reported Isomorph bug ("does not support fee-on-transfer tokens" — assuming the amount transferred equals the amount received) has a structural analog in the Polkadot SDK's XCM `ERC20Transactor`, which is the `TransactAsset` implementation used to let XCM treat `pallet-revive`-deployed ERC20 contracts as XCM-transactable fungible assets on Asset Hub Westend/Rococo [1](#0-0) . Unlike native `pallet-balances`/`pallet-assets` transfers (whose ledgers are the source of truth and cannot silently apply an extra "fee"), this transactor calls into an arbitrary externally-deployed smart contract's `transfer()` function and then trusts the boolean return value, crediting/debiting XCM's internal holding register with the *requested* amount rather than measuring the actual balance delta.

### Finding Description
`ERC20Transactor::withdraw_asset_with_surplus` withdraws an ERC20-backed XCM asset by calling `IERC20::transferCall { to: checking_address, value: amount }` on the target contract via `pallet_revive::Pallet::<T>::bare_call`. If the call succeeds and the ABI-decoded return value is `true`, the code unconditionally creates an XCM holding credit for the full `amount` requested: [2](#0-1) 

Likewise, `deposit_asset_with_surplus` transfers `amount` from the checking account to the beneficiary and, on a `true` return, treats the deposit as fully successful for the full `amount`: [3](#0-2) 

Neither function reads the ERC20 contract's `balanceOf` before and after the transfer to determine the actual amount moved — it only checks the boolean success return of `transfer()`, exactly the same class of assumption criticized in the Isomorph report ("assumes that when an amount x of tokens is transferred, the amount received is the same amount x"). This differs from the rest of the codebase where fees/deductions (e.g. XCM delivery fees, `take_delivery_fee_from_assets`) are computed and accounted for explicitly in Rust code, not by an opaque external contract call whose semantics the runtime cannot control [4](#0-3) .

Any ERC-20 contract implementing a transfer fee, rebase, or deflationary burn — e.g. via `pallet-revive`'s "AllowEVMBytecode" support for arbitrary EVM/PolkaVM contracts [5](#0-4)  — would cause the intermediate "checking account" (`ERC20TransfersCheckingAccount`, a chain-controlled `PalletId`-derived account used to stage withdrawals/deposits) to actually hold less than the amount XCM's holding register believes was withdrawn/deposited [6](#0-5) .

### Impact Explanation
Because the `Erc20Credit` imbalance type used to represent the holding-register credit is not backed by an actual runtime ledger — it is a bespoke `ImbalanceAccounting` wrapper around a plain `u128` — the holding register's book value can permanently diverge from the checking account's real ERC20 balance: [7](#0-6) 

Concretely: a user withdraws a fee-on-transfer ERC20 (`WithdrawAsset`/reserve-transfer via `pallet-xcm`, a permissionless, signed-origin dispatchable already wired into Asset Hub's `AssetTransactors` tuple) causing `checking_address` to receive `amount - fee` while the XCM program proceeds believing `amount` is held. Downstream instructions (`DepositAsset`, `DepositReserveAsset`, cross-chain reserve transfers minting a derivative asset on another chain) then operate on the inflated `amount`. Depending on how the checking account is later drained across multiple XCM executions, this can (a) cause `deposit_asset_with_surplus` calls to fail once the checking account is drained below what later holding credits assume (denial of service for legitimate transfers), or (b) if the checking account is used to back reserve-transferred derivative assets minted on other chains, produce unbacked/over-issued derivative asset supply relative to the real ERC20 collateral held in the checking account — the same "less collateral than assumed" impact flagged as Medium in the original report, but here manifesting as reserve under-collateralization rather than vault under-collateralization.

### Likelihood Explanation
Reaching this code path requires only:
1. Deploying an arbitrary EVM/PolkaVM contract via `pallet-revive` implementing the `IERC20` interface with a transfer fee/burn (no privileged role needed; `UploadOrigin`/`InstantiateOrigin` are `EnsureSigned` [8](#0-7) ).
2. Referencing that contract's address as an `AccountKey20` XCM `Location`/`AssetId` in a normal, permissionless `pallet_xcm` extrinsic (`execute`, `transfer_assets`, `limited_reserve_transfer_assets`, etc.), which is exactly the intended use case documented for the `ERC20Transactor` feature [9](#0-8) .

I was **not able to fully verify** (index limits / final iteration) whether `ERC20Matcher` (referenced in `cumulus/parachains/runtimes/assets/common/src/lib.rs` and `asset-hub-westend/src/xcm_config.rs`) applies any allowlist/registration restriction on which contract addresses can be matched as ERC20 XCM assets, which would materially affect whether *any* attacker-deployed contract qualifies or only pre-approved ones. This is an open question that must be resolved by reading `ERC20Matcher`'s implementation before treating this as conclusively exploitable without restriction. Likewise, I could not fully trace how (or whether) the checking-account balance is subsequently used to back cross-chain reserve/derivative-asset issuance in the current runtime configuration, which is necessary to confirm the unbacked-issuance impact versus a milder DoS/self-limiting failure.

### Recommendation
In `ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, query the ERC20 contract's `balanceOf` for the checking account (and/or sender/beneficiary) before and after the `transfer()` call, and use the observed balance delta — not the requested `amount` — to size the `AssetsInHolding` credit/debit, mirroring the "measure balance before and after" remediation recommended in the original report.

### Proof of Concept
Not executed. This requires: (1) confirming `ERC20Matcher`'s exact matching rules (unverified from available index), (2) deploying a fee-on-transfer PolkaVM/EVM contract fixture under `substrate/frame/revive/fixtures/contracts/` similar to the existing `MyTokenFake` non-standard-return fixture already used in Asset Hub Westend integration tests [10](#0-9) , and (3) running a `pallet_xcm::execute` withdraw/deposit through `ERC20Transactor` while asserting the checking account's real ERC20 balance versus the XCM holding-register amount. No test was run against a live network or reference runtime; this write-up documents the discovered code-level analog and its unresolved verification gaps rather than a completed, executed reproduction.

### Citations

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs (L213-219)
```rust
parameter_types! {
	/// Taken from the real gas and deposits of a standard ERC20 transfer call.
	pub const ERC20TransferGasLimit: Weight = Weight::from_parts(500_000_000_000, 10 * 1024 * 1024);
	pub const ERC20TransferStorageDepositLimit: Balance = 10_200_000_000;
	pub ERC20TransfersCheckingAccount: AccountId = PalletId(*b"py/revch").into_account_truncating();
	pub DapBufferAccount: AccountId = pallet_dap::Pallet::<Runtime>::buffer_account();
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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L185-207)
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
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L252-298)
```rust
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

**File:** polkadot/xcm/xcm-executor/src/lib.rs (L1198-1227)
```rust
			DepositReserveAsset { assets, dest, xcm } => {
				self.transactional_process(|self_ref| {
					let mut assets = self_ref.holding.saturating_take(assets);
					// When not using `PayFees`, nor `JIT_WITHDRAW`, delivery fees are paid from
					// transferred assets.
					let maybe_delivery_fee_from_assets = if self_ref.fees.is_empty() && !self_ref.fees_mode.jit_withdraw {
						// Deduct and return the part of `assets` that shall be used for delivery fees.
						self_ref.take_delivery_fee_from_assets(&mut assets, &dest, FeeReason::DepositReserveAsset, &xcm)?
					} else {
						None
					};
					let mut message = Vec::with_capacity(xcm.len() + 2);
					tracing::trace!(target: "xcm::DepositReserveAsset", ?assets, "Assets except delivery fee");
					Self::do_reserve_deposit_assets(
						assets,
						&dest,
						&mut message,
						Some(&self_ref.context),
					)?;
					// clear origin for subsequent custom instructions
					message.push(ClearOrigin);
					// append custom instructions
					message.extend(xcm.0.into_iter());
					if let Some(delivery_fee) = maybe_delivery_fee_from_assets {
						// Put back delivery_fee in holding register to be charged by XcmSender.
						self_ref.holding.subsume_assets(delivery_fee);
					}
					self_ref.send(dest, Xcm(message), FeeReason::DepositReserveAsset)?;
					Ok(())
				})
```

**File:** substrate/bin/node/runtime/src/lib.rs (L1556-1590)
```rust
impl pallet_revive::Config for Runtime {
	type Time = Timestamp;
	type Balance = Balance;
	type Currency = Balances;
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type RuntimeOrigin = RuntimeOrigin;
	type DepositPerItem = DepositPerItem;
	type DepositPerChildTrieItem = DepositPerChildTrieItem;
	type DepositPerByte = DepositPerByte;
	type WeightInfo = pallet_revive::weights::SubstrateWeight<Self>;
	type Precompiles = (
		ERC20<Self, InlineIdConfig<0x1>, Instance1>,
		ERC20<Self, InlineIdConfig<0x2>, Instance2>,
		VestingPrecompile<Self>,
	);
	type AddressMapper = pallet_revive::AccountId32Mapper<Self>;
	type RuntimeMemory = ConstU32<{ 128 * 1024 * 1024 }>;
	type PVFMemory = ConstU32<{ 512 * 1024 * 1024 }>;
	type UploadOrigin = EnsureSigned<Self::AccountId>;
	type InstantiateOrigin = EnsureSigned<Self::AccountId>;
	type RuntimeHoldReason = RuntimeHoldReason;
	type CodeHashLockupDepositPercent = CodeHashLockupDepositPercent;
	type ChainId = ConstU64<420_420_420>;
	type NativeToEthRatio = ConstU32<1_000_000>; // 10^(18 - 12) Eth is 10^18, Native is 10^12.
	type FindAuthor = <Runtime as pallet_authorship::Config>::FindAuthor;
	type AllowEVMBytecode = ConstBool<true>;
	type FeeInfo = pallet_revive::evm::fees::Info<Address, Signature, EthExtraImpl>;
	type MaxEthExtrinsicWeight = MaxEthExtrinsicWeight;
	type DebugEnabled = ConstBool<false>;
	type AutoMap = ConstBool<false>;
	type GasScale = ConstU32<1000>;
	type OnBurn = ();
	type Deposit = ();
}
```

**File:** prdoc/stable2506/pr_7762.prdoc (L1-19)
```text
# Schema: Polkadot SDK PRDoc Schema (prdoc) v1.0.0
# See doc at https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/prdoc/schema_user.json

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

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2026-2081)
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
}
```
