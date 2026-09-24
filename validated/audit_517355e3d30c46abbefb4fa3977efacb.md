### Title
`ERC20Transactor::withdraw_asset_with_surplus` treats a non-`bool`-returning ERC20 `transfer()` as a hard failure even though the on-chain token transfer already succeeded, permanently stranding user funds in the checking account - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor` (wired into Asset Hub's XCM config via `assets_common::ERC20Transactor`, referenced in `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`) implements `TransactAsset::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` by invoking an ERC20 token contract deployed under `pallet-revive` and strictly ABI-decoding its return data as a `bool` via `IERC20::transferCall::abi_decode_returns_validate`. This is the exact same "boolean return assumption" pattern flagged in the referenced Sherlock report (GatewaySend / USDT `transferFrom` void-return incompatibility): any ERC20 contract that returns no data on success (the common USDT-style non-standard implementation) causes the decode to fail, and the transactor converts that decode failure into `XcmError::FailedToTransactAsset("ERC20 contract result couldn't decode")` — even though the underlying `transfer` call already executed and moved the tokens.

### Finding Description
In `withdraw_asset_with_surplus` [1](#0-0) , the transactor calls the token contract's `transfer` function via `pallet_revive::Pallet::<T>::bare_call` to move the user's tokens into `TransfersCheckingAccount`. If the underlying PVM/EVM-compatible contract call does **not** revert but returns no/short return data (a void-return `transfer`, matching non-standard tokens like USDT on Ethereum), the code path is: [2](#0-1) 

- `result` is `Ok`, `return_value.did_revert()` is `false` (the transfer genuinely succeeded and balances were already mutated inside the contract's storage).
- `IERC20::transferCall::abi_decode_returns_validate(&return_value.data)` fails to decode a `bool` from empty/short data, producing `Err`.
- The transactor maps this decode error to `Err(XcmError::FailedToTransactAsset("ERC20 contract result couldn't decode"))`.

Crucially, this is a **withdraw** operation: the real ERC20 token balance transfer to the checking account has already been committed on-chain (the `bare_call` executed and did not revert), but the XCM executor is told the withdraw failed and never creates the corresponding `AssetsInHolding` credit (`Erc20Credit`) for the amount. The same decode-failure pattern occurs symmetrically in `deposit_asset_with_surplus` [3](#0-2) , where a successful-but-void-return transfer out of the checking account is likewise reported as failed even though the beneficiary already received the tokens.

The root assumption — that any ERC20-compatible contract registered for this transactor always returns a strict `bool` on `transfer`/`transferFrom` — mirrors the Sherlock report's root cause precisely: `IERC20::transferCall` (`substrate/primitives/ethereum-standards/src/IERC20.sol`) declares `returns (bool)`, and the transactor's error handling assumes decode failure means "transfer failed," when in this specific fungible/ERC20-registration path the contract call's revert status (`did_revert()`) — not the ABI-decoded boolean — is the authoritative success signal.

### Impact Explanation
For `withdraw_asset_with_surplus`, a decode failure after a non-reverted call means tokens have left the user's balance and landed in `TransfersCheckingAccount`, but the XCM executor treats the whole withdraw as an error and unwinds/fails the XCM program without any compensating credit or refund path back to the user (no `deposit_asset` is invoked with those funds, since no `AssetsInHolding` was ever created). This constitutes a fund-locking/loss condition: funds that were actually transferred are not represented anywhere in the XCM holding register, and there is no visible on-chain rollback of the ERC20 contract-level transfer (the contract's own storage already reflects a completed transfer; XCM's failure is purely at the interpretation layer, not the state layer). This differs from — and is more severe than — the original Sherlock report, which merely produced a reverted, no-op transaction wasting gas; here the analog can result in tokens becoming stuck in the checking account with the sending message erroring out.

### Likelihood Explanation
This requires that `ERC20Transactor` is configured with a token contract whose `transfer`/`transferFrom` implementation does not return a `bool` (void-return / non-standard ERC20, analogous to real-world USDT). Reachability depends on which specific tokens are registered under `ERC20Matcher`/`Matcher: MatchesFungibles<H160, u128>` for a concrete runtime deployment; I was not able to confirm from the indexed files whether `ERC20Transactor` is actually included in the live `AssetTransactors` tuple of `asset-hub-westend`'s `xcm_config.rs` (only import references were found, not the final transactor composition), nor whether any currently-deployed contract on Asset Hub via `pallet-revive` uses a non-standard void-return `transfer`. Given the code explicitly imports and re-exports `ERC20Transactor` in `cumulus/parachains/runtimes/assets/common/src/lib.rs` and asset-hub-westend's `xcm_config.rs` references it twice, the wiring path is plausible but not fully confirmed as active/reachable from an unprivileged XCM message without further inspection of the full `AssetTransactors` tuple and the on-chain registered ERC20 contracts, which the index did not surface.

### Recommendation
In both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, do not treat an ABI-decode failure on non-empty-but-non-reverted return data as equivalent to "transfer failed." Follow the same safe-transfer pattern recommended in the analogous report: treat `!did_revert()` combined with `return_value.data.is_empty()` as success (mirroring `TransferHelper`/`SafeERC20` semantics that accept void returns), and only treat a non-empty, decodable `false` return as an actual failure. Alternatively, since success/failure is already authoritatively signaled by `did_revert()`, drop the strict boolean decode requirement for a non-reverted call whose return data is empty.

### Proof of Concept
No executable PoC was run. This analysis is based on static reading of `cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs` and its call sites; I could not verify a full local Rust/FRAME integration test where a `pallet-revive` contract implementing a void-return `transfer` is registered as the target of `ERC20Transactor::withdraw_asset_with_surplus`/`deposit_asset_with_surplus`, nor confirm final inclusion of `ERC20Transactor` in a live `AssetTransactors` tuple, within the available tool budget. The existing test suite for this file was not located in the index (only usages in `erc20_transactor.rs` itself and `xcm_config.rs` were found), so guard behavior on empty/void return data is unverified against actual test coverage. A background Devin session with full repository/terminal access would be needed to (1) confirm `ERC20Transactor`'s presence in the production `AssetTransactors` tuple, (2) write a `pallet-revive` fixture contract with a void-return `transfer`, and (3) execute an integration test driving `withdraw_asset_with_surplus`/`deposit_asset_with_surplus` against it to observe the described fund-stranding behavior.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L166-181)
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
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L185-216)
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
			}
		} else {
			tracing::debug!(target: "xcm::transactor::erc20::withdraw", ?result, "Error");
			// This error could've been duplicate smart contract, out of gas, etc.
			// If the issue is gas, there's nothing the user can change in the XCM
			// that will make this work since there's a hardcoded gas limit.
			Err(XcmError::FailedToTransactAsset("ERC20 contract execution errored"))
		}
	}
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
