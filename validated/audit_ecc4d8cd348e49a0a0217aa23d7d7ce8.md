## Analog Found

The reported bug class — ERC20 interfaces that assume a strict boolean return from `transfer`/`transferFrom`, causing non-compliant tokens (USDT-style) to make the caller treat a successful transfer as a failure and get funds stuck — has a direct analog in the new ERC20 Asset Transactor added to bridge XCM asset handling to `pallet-revive` contracts.

### Title
ERC20 tokens with non-standard `transfer` return values get permanently stuck in `ERC20Transactor`'s checking account - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor` implements `TransactAsset` for XCM assets backed by ERC-20 contracts deployed under `pallet-revive`. Both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus` invoke `IERC20::transferCall` via `pallet_revive::Pallet::<T>::bare_call` and then strictly decode the return value with `alloy`'s `abi_decode_returns_validate`, which requires the callee to return an ABI-encoded `bool` (32 bytes). USDT-style tokens that omit the return value on `transfer` will make this decode fail even though the underlying token transfer already succeeded and mutated on-chain balances.

### Finding Description
`withdraw_asset_with_surplus` performs the actual value movement by calling the ERC20 contract's `transfer` function to move tokens from the user to an internal `TransfersCheckingAccount` escrow, then requires a decodable `bool` return: [1](#0-0) 

If the token contract does not return `true`/`false` ABI-encoded (as is the case for real USDT and USDT-like tokens), `abi_decode_returns_validate` returns an error and the function returns `Err(XcmError::FailedToTransactAsset(...))`: [2](#0-1) 

Crucially, the `bare_call` to `transfer` has already executed and mutated the token contract's storage — the tokens have already moved from the user's account to the checking account — *before* the return-value decode is attempted. Because the decode fails, `withdraw_asset_with_surplus` never produces an `AssetsInHolding` credit for these tokens, so the XCM executor has no record that these tokens exist in holding. The withdrawal is reported as failed, aborting/erroring the XCM instruction, while the real ERC20 balance has already been debited from the user and credited to the checking account with no way for the executor to reclaim or re-attempt crediting it.

The same class of issue applies to `deposit_asset_with_surplus`, which transfers from the checking account to the beneficiary and again requires a decodable boolean: [3](#0-2) 

Here a non-compliant token's successful transfer (with no properly decodable return) is treated as a failure, returning `Err((what, XcmError::FailedToTransactAsset(...)))` even though the real tokens already left the checking account to the beneficiary. The `what` (the internal `Erc20Credit` accounting entry, not the real token) is then handled by the XCM executor's normal error/trap path (e.g., `AssetsTrapped`), creating a duplicate/incorrect internal accounting entry relative to the real on-chain ERC20 state — since the checking account's real balance was already decremented by the successful low-level transfer, but the executor believes the deposit failed and may attempt to retry or trap the corresponding internal credit.

This is wired into a real runtime: `ERC20Transactor` is referenced in the Asset Hub Westend XCM configuration and matches AssetIds of the form `AccountKey20` per the corresponding feature PR: [4](#0-3) [5](#0-4) 

The `IERC20` Solidity interface used to encode/decode the call explicitly declares `transfer`/`transferFrom` as returning `bool`, matching the exact interface shape that the original report calls out as incompatible with USDT: [6](#0-5) 

### Impact Explanation
Any ERC20 contract that is USDT-like (omits the boolean return on `transfer`) and is registered/matched as an XCM asset via `ERC20Transactor` will have its withdrawals silently move real tokens into the escrow/checking account without producing a corresponding trackable credit for the XCM executor, and deposits will similarly move tokens out of the checking account while the executor treats the operation as failed. In both cases the mismatch between real ERC20 contract state (tokens actually moved) and the internal `AssetsInHolding`/trap accounting means user funds routed through this transactor can become permanently stranded in the checking account or become inconsistent with the internal ledger — the exact "permanently stuck" outcome described in the original report, now surfaced against a real cross-chain asset-movement path rather than isolated contract storage.

### Likelihood Explanation
Reachability requires only that an ERC20 asset non-compliant with strict boolean ABI returns be matched by the configured `Matcher: MatchesFungibles<H160, u128>` for a chain using `ERC20Transactor` (currently wired for Asset Hub Westend). This requires no privileged role, governance action, or malicious infrastructure — any ordinary signed user performing `pallet_xcm::transfer_assets`/`execute` with an asset ID pointing at such a token contract, or receiving one via reserve transfer, would trigger the path. Whether arbitrary/attacker-deployed ERC20 contracts can be registered as such asset IDs without permissioned governance action was not fully confirmed in the available index (the registration/`Matcher` configuration for Asset Hub Westend's ERC20 asset IDs was not fully traced), which is the main source of remaining uncertainty in likelihood — if registration of the underlying contract requires governance approval, likelihood is Low; if any deployed contract address can be referenced permissionlessly as long as it satisfies the location pattern, likelihood is Medium.

### Recommendation
- Do not require strict decode success as the sole success signal for the `transfer`/`transferFrom` low-level call. Detect "no return data" (`return_value.data.is_empty()`) as a distinct, accepted success case (mirroring `SafeERC20`'s "ignore missing return value" semantics), rather than lumping empty-returndata cases into `FailedToTransactAsset` after the real transfer has already occurred.
- Alternatively, perform a pre/post balance check (`balanceOf` before/after the `bare_call`) rather than relying purely on the ABI-decoded return value, so that success/failure tracking in `AssetsInHolding` matches the actual on-chain token movement regardless of whether the token conforms to strict OpenZeppelin `IERC20` semantics.
- Add integration tests using a `pallet-revive` fixture contract that mimics USDT's `transfer` (returns no data) to confirm `withdraw_asset_with_surplus`/`deposit_asset_with_surplus` behave correctly and do not desynchronize checking-account balances from `AssetsInHolding` accounting.

### Proof of Concept
No executable PoC was run against a live/test network per instructions. Evidence supporting the analog is purely from static code inspection:
- Confirmed `bare_call` (real, stateful `transfer` execution) occurs before the return-value decode in both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`: [7](#0-6) 
- Confirmed `abi_decode_returns_validate` is the sole gate for treating the transfer as successful, with no fallback for empty/non-standard return data: [8](#0-7) 
- Confirmed real runtime wiring for Asset Hub Westend: [9](#0-8) 

No unit/integration test in the indexed portion of `erc20_transactor.rs`'s test suite (not found in the index) exercises a non-standard/no-return-value ERC20 token, so a minimal reproduction (a `pallet-revive` fixture contract whose `transfer` returns no data, registered as the matched asset, then exercised through `withdraw_asset_with_surplus`) would need to be authored and run by a background engineer with full repository/test-harness access; this was not executed here due to ask-only/index-based access constraints, not because it was disproven.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L166-194)
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
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L270-298)
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
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs (L1-30)
```rust
// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{
	AccountId, AllPalletsWithSystem, Assets, Balance, Balances, BaseDeliveryFee, CollatorSelection,
	DepositPerByte, DepositPerItem, FeeAssetId, ForeignAssets, GeneralAdmin, ParachainInfo,
	ParachainSystem, PolkadotXcm, PoolAssets, Runtime, RuntimeCall, RuntimeEvent,
	RuntimeHoldReason, RuntimeOrigin, ToRococoXcmRouter, TransactionByteFee, Uniques, WeightToFee,
	XcmpQueue,
};
use alloc::{collections::BTreeSet, vec, vec::Vec};
use assets_common::{
	matching::{
		IsForeignConcreteAsset, NonTeleportableAssetFromTrustedReserve, ParentLocation,
		TeleportableAssetWithTrustedReserve,
	},
	TrustBackedAssetsAsLocation,
};
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

**File:** substrate/primitives/ethereum-standards/src/IERC20.sol (L41-46)
```text
    /// @dev Moves a `value` amount of tokens from the caller's account to `to`.
    ///
    /// Returns a boolean value indicating whether the operation succeeded.
    ///
    /// Emits a {Transfer} event.
    function transfer(address to, uint256 value) external returns (bool);
```
