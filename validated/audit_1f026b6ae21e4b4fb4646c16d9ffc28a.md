### Title
`ERC20Transactor` XCM asset transactor reverts on non-standard ERC-20 tokens (e.g. USDT-style `transfer`/`approve` without `bool` return) - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` move ERC-20 tokens by issuing a raw `IERC20::transferCall` against an arbitrary contract address taken from the XCM asset's `Location` (an `AccountKey20` junction), and then strictly ABI-decode the return data as a `bool` via `IERC20::transferCall::abi_decode_returns_validate`. This mirrors exactly the bug class in the referenced report: many real-world, widely-used ERC-20 tokens (most famously mainnet USDT, whose `transfer`/`transferFrom`/`approve` functions do not return a `bool` at all) will make the ABI decode fail even though the underlying token call succeeded, permanently breaking any XCM flow that references such a token. [1](#0-0) [2](#0-1) 

### Finding Description
`ERC20Transactor` is a `TransactAsset` implementation added specifically to let Asset Hub (via `pallet-revive`) treat externally deployed EVM ERC-20 contracts as XCM-transactable fungible assets, matched by their `H160` contract address embedded in an `AccountKey20` XCM `Location` junction, as described in the feature PR doc. [3](#0-2) 

In `withdraw_asset_with_surplus`, the transactor builds an `IERC20::transferCall` and executes it against the ERC-20 contract via `pallet_revive::Pallet::<T>::bare_call`. It then checks `return_value.did_revert()` and, if not reverted, calls `IERC20::transferCall::abi_decode_returns_validate(&return_value.data)` to obtain the expected `bool` success flag: [4](#0-3) 

`deposit_asset_with_surplus` does the same pattern on the deposit leg: [5](#0-4) 

This is the exact analog of the reported vulnerability class: the code assumes strict EIP-20 compliance (a `bool` ABI return value on `transfer`/`transferFrom`) from an attacker/user-controlled, arbitrary external contract address. Tokens that do not return this value — such as mainnet USDT, whose real deployed `transfer(address,uint256)` has no return value at all — will produce empty return data on success. `abi_decode_returns_validate` on empty bytes fails to decode a `bool`, and the code treats this as a hard failure (`XcmError::FailedToTransactAsset("ERC20 contract result couldn't decode")`), even though the token contract itself executed the transfer correctly and mutated its own storage/balances.

Unlike the SDK's own `pallet-assets-precompiles` ERC-20 precompile (which is the SDK's own implementation of the ERC-20 interface and unconditionally returns `true` via `IERC20::approveCall::abi_encode_returns(&true)` — so it can never trigger this class of bug because it controls both sides of the ABI contract) [6](#0-5) 
the `ERC20Transactor` calls out to an *arbitrary, attacker-chosen* deployed contract address supplied through the XCM asset id/location matcher, i.e. code the runtime does not control and cannot assume is EIP-20-return-value-compliant.

### Impact Explanation
Any real-world token deployed with the widely-known "USDT-style" missing-return-value quirk (transfer/transferFrom without `bool` return) becomes **permanently unusable** through this XCM transactor: every `withdraw_asset_with_surplus` and `deposit_asset_with_surplus` invocation for that token will fail to decode the return data and abort with `XcmError::FailedToTransactAsset`, even though the underlying transfer executed successfully on the token contract. Depending on transactional ordering/rollback semantics of the XCM executor, this can also cause an asset-accounting mismatch: the ERC-20 contract's own state may have already moved the tokens (transfer executed, not reverted) while the XCM executor is told the operation failed and does not credit the corresponding `AssetsInHolding` — a deterministic, irreversible loss/inconsistency for any XCM program that interacts with such non-compliant tokens. This is a functional break/DoS (and potential accounting mismatch) rather than direct fund theft, warranting Medium/High severity depending on how the surrounding XCM executor handles a failed `TransactAsset` after the inner call already committed state changes on the external contract side.

### Likelihood Explanation
Likelihood is high for any deployment that enables `ERC20Transactor` (confirmed wired into `asset-hub-westend` per the grep results and the feature prdoc) and allows XCM programs referencing arbitrary `AccountKey20` locations matched by the configured `Matcher`. No privileged role is required — any user capable of constructing/submitting an XCM message (e.g., via a reserve transfer or `Transact`/`InitiateTransfer` naming the non-compliant ERC-20's contract address as the asset id) can trigger the failure path with a token they don't even need to own; deposit/withdraw is attempted against the real, already-deployed token contract's non-standard interface. The report's underlying premise — that real deployed tokens genuinely lack the `bool` return (USDT being the canonical example) — is a proven, widely documented fact, not a hypothetical.

### Recommendation
Do not use strict ABI decoding (`abi_decode_returns_validate`) as the sole success criterion for `transfer`/`transferFrom` calls against externally supplied ERC-20 contracts. Instead:
- Treat empty return data (`return_value.data.is_empty()`) on a non-reverted call as success, matching OpenZeppelin's `SafeERC20` semantics (only decode a `bool` when return data is present; otherwise trust `did_revert()`).
- Consider verifying the actual balance delta on the involved accounts (checking token balance before/after the call) instead of relying purely on the encoded return value, to guard against contracts that return `true`/no data but do not actually move the expected amount.
- Apply the same fix symmetrically to both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`.

### Proof of Concept
Failed guard identified: `IERC20::transferCall::abi_decode_returns_validate(&return_value.data)` in both `withdraw_asset_with_surplus` (line ~191) and `deposit_asset_with_surplus` (line ~276) unconditionally expects ABI-encoded `bool` return data. [7](#0-6) [5](#0-4) 

Deployment evidence: the transactor is wired into `asset-hub-westend`'s XCM config (`ERC20Transactor` referenced in `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`), and the feature is documented as enabling arbitrary externally-deployed ERC-20 contracts (matched by `AccountKey20` address) to be XCM-transactable via `pallet-revive`. [3](#0-2) 

I was not able to execute a live local Rust/XCM integration test against this specific path within this session (no code execution tooling available in this ask-only investigation), so this analysis is based on static code reading and the documented behavior of `abi_decode_returns_validate`/`pallet_revive::bare_call`, not a confirmed runtime execution trace. A background engineering session with test-harness access would be needed to write a `pallet-revive` fixture contract that mimics USDT's no-bool-return `transfer` and drive it through `ERC20Transactor::deposit_asset_with_surplus`/`withdraw_asset_with_surplus` in a `#[test]` to obtain concrete pass/fail evidence and confirm whether any partial-state-mutation/accounting-mismatch occurs on the failure path.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L166-216)
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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L250-298)
```rust
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

**File:** substrate/frame/assets/precompiles/src/lib.rs (L343-432)
```rust
	/// Execute the approve call.
	///
	/// Implements ERC-20 set semantics: `approve(spender, N)` sets the allowance to exactly `N`
	/// rather than adding to it. When overwriting a non-zero allowance, the existing approval is
	/// cancelled first so the new value replaces (not accumulates with) the old one.
	///
	/// `call.value > Balance::MAX` (the `type(uint256).max` "infinite allowance" idiom)
	/// saturates the stored allowance at `Balance::MAX`. The `Approval` event carries the
	/// raw `call.value`.
	fn approve(
		asset_id: <Runtime as Config<Instance>>::AssetId,
		call: &IERC20::approveCall,
		env: &mut impl Ext<T = Runtime>,
	) -> Result<Vec<u8>, Error> {
		use frame_support::traits::fungibles::approvals::Inspect as ApprovalsInspect;

		// Reserve worst-case gas upfront, then refund the unused portion.
		let worst_case = <Runtime as Config<Instance>>::WeightInfo::allowance()
			.saturating_add(<Runtime as Config<Instance>>::WeightInfo::cancel_approval())
			.saturating_add(<Runtime as Config<Instance>>::WeightInfo::approve_transfer());
		let charged = env.charge(worst_case)?;

		let owner = Self::caller(env)?;
		let owner_account =
			<Runtime as pallet_revive::Config>::AddressMapper::to_account_id(&owner);
		let spender: H160 = call.spender.into_array().into();
		let spender_account = env.to_account_id(&spender);
		// Saturate: `type(uint256).max` is the standard "infinite allowance" idiom and must
		// not revert at the conversion boundary.
		let new_amount: <Runtime as Config<Instance>>::Balance = call.value.unique_saturated_into();

		let current = pallet_assets::Pallet::<Runtime, Instance>::allowance(
			asset_id.clone(),
			&owner_account,
			&spender_account,
		);

		let actual_weight;
		if new_amount.is_zero() {
			if !current.is_zero() {
				// Revoke: use the pallet's cancel logic to remove the approval and
				// unreserve the deposit.
				pallet_assets::Pallet::<Runtime, Instance>::do_cancel_approval(
					&asset_id,
					&owner_account,
					&spender_account,
				)?;
				actual_weight = <Runtime as Config<Instance>>::WeightInfo::allowance()
					.saturating_add(<Runtime as Config<Instance>>::WeightInfo::cancel_approval());
			} else {
				// 0→0 no-op: only the allowance read was needed.
				actual_weight = <Runtime as Config<Instance>>::WeightInfo::allowance();
			}
		} else {
			// If there's an existing non-zero allowance, cancel it first so we
			// overwrite (not accumulate) — matching ERC-20 spec semantics.
			// NOTE: This does not mitigate the well-known ERC-20 approve front-running
			// race condition. Callers concerned about this should approve to 0 first,
			// or use increaseAllowance/decreaseAllowance if available.
			if !current.is_zero() {
				pallet_assets::Pallet::<Runtime, Instance>::do_cancel_approval(
					&asset_id,
					&owner_account,
					&spender_account,
				)?;
				actual_weight = worst_case;
			} else {
				actual_weight = <Runtime as Config<Instance>>::WeightInfo::allowance()
					.saturating_add(<Runtime as Config<Instance>>::WeightInfo::approve_transfer());
			}
			pallet_assets::Pallet::<Runtime, Instance>::do_approve_transfer(
				asset_id,
				&owner_account,
				&spender_account,
				new_amount,
			)?;
		}
		env.adjust_gas(charged, actual_weight);

		Self::deposit_event(
			env,
			IERC20Events::Approval(IERC20::Approval {
				owner: owner.0.into(),
				spender: call.spender,
				value: call.value,
			}),
		)?;

		Ok(IERC20::approveCall::abi_encode_returns(&true))
	}
```
