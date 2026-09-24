Based on my research, I found a concrete analog of the "transfer of zero amount reverts" bug class in the `polkadot-sdk` repository, in the ERC20 asset transactor used by Asset Hub for bridging Ethereum-side ERC20 tokens into XCM.

### Title
`ERC20Transactor` unconditionally calls ERC20 `transfer(to, 0)` for zero-amount holdings, causing XCM asset movement to fail for tokens that revert on zero-value transfers - (File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs)

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` extract `(asset_id, amount)` via `Matcher::matches_fungibles(what)` and then unconditionally build and dispatch a Solidity `IERC20::transferCall{ to, value: amount }` through `pallet_revive::Pallet::<T>::bare_call`, without ever checking `amount > 0` before making the external call, mirroring the exact pattern flagged in the report for `TellerV2::lenderAcceptBid`.

### Finding Description
`ERC20Transactor` is a `TransactAsset` implementation wired into Asset Hub Westend's XCM configuration (`cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`) to let XCM programs move real ERC20 tokens deployed as `pallet-revive` contracts. [1](#0-0) 
`withdraw_asset_with_surplus` matches the fungible amount and, regardless of its value, ABI-encodes `IERC20::transferCall { to: checking_address, value: EU256::from(amount) }` and issues a `bare_call` into the real ERC20 contract. [2](#0-1) 
`deposit_asset_with_surplus` does the same for the deposit direction: it extracts the amount from the XCM holding and calls `IERC20::transferCall` unconditionally, checking only for revert/decode failures afterward, never for `amount == 0`. [3](#0-2) 
If the underlying deployed ERC20 contract is a non-standard implementation that reverts on a zero-value `transfer`/`transferFrom` (a documented real-world quirk, cited in the original report for tokens like LEND), the `bare_call` returns `did_revert() == true`, and the transactor maps this to `XcmError::FailedToTransactAsset("ERC20 contract reverted")`, aborting the enclosing XCM instruction.

While the top-level XCM wire format enforces that a decoded `Fungible` amount can never be zero (`Fungibility::Decode` rejects `Fungible(0)` at the wire boundary): [4](#0-3) 
that guarantee only applies to *externally decoded* multiassets. Internal XCM-executor logic can and does construct zero-valued `Asset`/`AssetsInHolding` entries programmatically, bypassing the decode-time check — for example `SwapFirstAssetTrader::refund_weight` explicitly builds `(asset.clone(), Fungible(0)).into()` as an "initial zero refund": [5](#0-4) 
and a related fix (`pr_11389.prdoc`) confirms the XCM executor genuinely produces zero-amount holding entries in normal (non-attacker) fee/refund flows that previously escaped into `AssetTrapped` events: [6](#0-5) 
This shows the precedent that zero-value fungible holdings are a reachable runtime condition inside the XCM executor even though wire-level messages cannot directly encode `Fungible(0)`.

### Impact Explanation
If a runtime registers an ERC20 asset via `ERC20Transactor` whose underlying contract reverts on zero-value transfers, any XCM path that ends up depositing or withdrawing exactly zero of that asset through this transactor (e.g., dust/change/fee-refund handling, or a `DepositAsset`/`InitiateTransfer` selecting a residual zero balance) will unexpectedly fail with `FailedToTransactAsset`, aborting that leg of the XCM program. Depending on where in the instruction sequence this occurs, this can trap already-withdrawn assets (`AssetTrapped`) or cause an otherwise-legitimate cross-chain transfer to fail non-deterministically, denying service for that specific asset without any attacker action — a legitimate ordinary user's XCM message becomes unprocessable.

### Likelihood Explanation
This requires no privileged role or malicious actor: an ordinary signed `pallet_xcm::execute`/XCM message from AssetHubWestend involving an ERC20 asset routed through `ERC20Transactor` is sufficient. It does, however, require (a) governance/config to have actually listed a non-standard ERC20 token that reverts on zero transfers, and (b) an execution path that produces a genuinely zero-amount transfer against that specific asset. I could not fully trace, within the available tools, a concrete end-to-end instruction sequence that forces a zero-amount holding entry to reach `ERC20Transactor::deposit_asset_with_surplus`/`withdraw_asset_with_surplus` specifically (as opposed to internal fee-refund holding manipulation which may not call `TransactAsset` at all). This uncertainty keeps the likelihood assessment tentative — the finding is a plausible robustness gap, not confirmed to be exploitable end-to-end.

### Recommendation
Add an explicit `if amount.is_zero() { return Ok(...) as a no-op }` guard in both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus` in `cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs`, before constructing/dispatching the `IERC20::transferCall`, mirroring the recommendation in the original report ("check if amount > 0 before transferring tokens").

### Proof of Concept
- **Failed guard identified**: absence of an `amount.is_zero()` check before the `IERC20::transferCall` dispatch in both transactor methods (lines ~159-169 and ~240-253 of `erc20_transactor.rs`).
- **Deployment evidence**: `ERC20Transactor` is actually configured in `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`, confirming it is production-wired code, not test-only.
- **PoC execution status**: Not executed. I have no code-execution or Rust/FRAME test-harness access in this session; I could not run an integration test to force a genuinely reachable zero-amount deposit/withdraw through this transactor and confirm the revert propagation end-to-end. This should be validated with a local `xcm-emulator`/FRAME integration test that (1) deploys a mock ERC20 contract that reverts on `transfer(_, 0)`, (2) registers it via `ERC20Transactor`, and (3) constructs an XCM program that drives a zero-amount deposit/withdraw of that asset (e.g., via a fee-refund or dust-handling path) to confirm `FailedToTransactAsset` is actually raised on a legitimate, non-privileged user flow.

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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L248-266)
```rust
		// We need to map the 32 byte beneficiary account to a 20 byte account.
		let eth_address = T::AddressMapper::to_address(&who);
		let address = Address::from(Into::<[u8; 20]>::into(eth_address));
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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L270-306)
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
		} else {
			tracing::debug!(target: "xcm::transactor::erc20::deposit", ?result, "Error");
			// This error could've been duplicate smart contract, out of gas, etc.
			// If the issue is gas, there's nothing the user can change in the XCM
			// that will make this work since there's a hardcoded gas limit.
			Err((what, XcmError::FailedToTransactAsset("ERC20 contract execution errored")))
		}
	}
```

**File:** polkadot/xcm/src/v4/asset.rs (L311-320)
```rust
impl Decode for Fungibility {
	fn decode<I: codec::Input>(input: &mut I) -> Result<Self, codec::Error> {
		match UncheckedFungibility::decode(input)? {
			UncheckedFungibility::Fungible(a) if a != 0 => Ok(Self::Fungible(a)),
			UncheckedFungibility::NonFungible(i) => Ok(Self::NonFungible(i)),
			UncheckedFungibility::Fungible(_) => {
				Err("Fungible asset of zero amount is not allowed".into())
			},
		}
	}
```

**File:** cumulus/primitives/utility/src/lib.rs (L523-528)
```rust
		let refund_asset = if let Some(asset) = &self.last_fee_asset {
			// create an initial zero refund in the asset used in the last `buy_weight`.
			(asset.clone(), Fungible(0)).into()
		} else {
			return None;
		};
```

**File:** prdoc/stable2603/pr_11389.prdoc (L1-11)
```text
title: 'Fix: AssetTrapped event with Fungible(0) due to `SwapFirstAssetTrader::buy_weight`
  for exact trades'
doc:
- audience: Runtime Dev
  description: "When `PayFees` contained the exact quoted fee, `SwapFirstAssetTrader::buy_weight`\
    \ produces zero swap change. This 0-amount credit was unconditionally wrapped\
    \ into an `AssetsInHolding` entry, which propagated through `fees` \u2192 `refund_surplus`\
    \ \u2192 `holding` \u2192 `drop_assets`, emitting an `AssetsTrapped` event with\
    \ `Fungible(0)` that fails to decode.\n\nThis PR simply guards that by checking\
    \ if value is 0 before putting it into the holding, and omitting the step if the\
    \ value is 0.\n\nCloses #11388"
```
