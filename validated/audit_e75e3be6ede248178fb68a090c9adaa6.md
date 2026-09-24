### Title
Tip funds burned on AssetHub are permanently lost when `add_tip` fails on BridgeHub, recorded only in unclaimable `LostTips` storage - ([File: bridges/snowbridge/pallets/system-frontend/src/lib.rs], [File: bridges/snowbridge/pallets/system-v2/src/lib.rs])

### Summary
A signed, permissionless user calling `snowbridge_pallet_system_frontend::Pallet::add_tip` on AssetHub has their tip asset swapped/burned for Ether *before* the destination pallet on BridgeHub validates whether the tip can actually be attached to the target message. If the BridgeHub-side `add_tip` fails (nonce already consumed / pending order not found), `pallet-system-v2` swallows the error, records the lost amount in `LostTips` and returns `Ok(())`. There is no extrinsic anywhere in the codebase that lets the sender reclaim the value recorded in `LostTips` - the funds are burned and irrecoverable, exactly analogous to the Fenix `PairFees` bug where collected value is tracked in an accounting structure that has no corresponding claim path.

### Finding Description
The user-facing entry point is `EthereumSystemFrontend::add_tip(origin, message_id, asset)` on AssetHub [1](#0-0) . Internally this calls `swap_fee_asset_and_burn`, which swaps the tip asset for Ether and then unconditionally burns it via `burn_for_teleport::<T::AssetTransactor>` [2](#0-1) . This burn happens synchronously and successfully *before* the pallet knows whether the corresponding message nonce still exists on BridgeHub.

After burning, the pallet builds and sends an XCM `Transact` to BridgeHub invoking `EthereumSystemCall::AddTip { sender, message_id, amount }` [1](#0-0) . On BridgeHub, `pallet-system-v2::add_tip` dispatches to `InboundQueue::add_tip` or `OutboundQueue::add_tip` [3](#0-2) .

- `InboundQueueV2::add_tip` fails with `AddTipError::NonceConsumed` if the message nonce has already been processed [4](#0-3) .
- `OutboundQueueV2::add_tip` fails with `AddTipError::UnknownMessage` if no `PendingOrders` entry exists for that nonce (e.g., already delivered/removed) [5](#0-4) .

When either call errors, `system-v2::add_tip` does **not** propagate the failure to fail the extrinsic. It instead records the lost amount against the sender in `LostTips` and still returns `Ok(())`: [3](#0-2) 

The `LostTips` storage doc comment itself confirms there is currently no recovery path: "Capturing the lost tips here supports implementing a recovery method in the future" [6](#0-5) . A search across the codebase for any claim/reclaim/refund extrinsic tied to `LostTips` returns nothing - no such call exists in `pallet-system-v2`, `pallet-system-frontend`, or elsewhere.

This is confirmed by an integration test that deliberately targets a non-existent outbound nonce, showing the tip is burned on AssetHub, the XCM to BridgeHub succeeds, the tip fails to attach, and the amount is only recorded in `LostTips` with `success: false` in the emitted event [7](#0-6) . A related historical fix (`prdoc/stable2509/pr_9746.prdoc`) shows the project has already had to patch a similar "tips lost because already burnt" bug once [8](#0-7) , indicating this class of bug is a recurring, real concern in this exact subsystem rather than a purely theoretical EVM analogy.

This differs from the nomination-pools `do_claim_trapped_balance`/`ClaimTrappedBalance` pattern, which is the *fixed* analog for a similar mismatch (delegated balance exceeding tracked points) and does provide a permissionless recovery function [9](#0-8) . No equivalent function exists for `LostTips`.

### Impact Explanation
Any ordinary AssetHub user who calls `add_tip` for a message nonce that has just been processed (a race that is trivially triggerable — relayers process messages continuously and nonces are consumed as soon as a message is relayed) or for an outbound nonce whose pending order has already been removed, permanently loses the DOT/asset value burned in `swap_fee_asset_and_burn`. This is a direct, deterministic loss of user funds with no privileged actor involved and no way to recover the funds — matching the "Protocol fees/collected value lost due to accounting gap with no claim path" bug class from the report, translated into the FRAME/XCM tip-topup mechanism.

### Likelihood Explanation
High likelihood: `add_tip` is a normal signed extrinsic reachable by any user with no special permissions [1](#0-0) . The race window between a user submitting a tip and the target message nonce being consumed by a relayer, or an outbound order being finalized/removed, is realistic and not attacker-privileged — it can occur simply due to normal relayer activity, and the integration test in the repo specifically exercises and confirms this exact failure path [7](#0-6) .

### Recommendation
Either (a) defer the burn/swap of the tip asset on AssetHub until BridgeHub confirms the tip was successfully attached (e.g., via a two-phase reserve-then-settle using XCM query/callback), or (b) implement the "recovery method" alluded to in the `LostTips` doc comment: add a permissionless extrinsic (mirroring `do_claim_trapped_balance`) that mints/reimburses the sender's recorded `LostTips` balance back on AssetHub, driven by an XCM message from BridgeHub back to the frontend pallet once a tip fails.

### Proof of Concept
- No PoC was executed against a live network; this analysis is based on static code tracing through the existing test suite.
- The existing integration test `tip_to_invalid_nonce_is_added_to_lost_tips` in `cumulus/parachains/integration-tests/emulated/tests/bridges/bridge-hub-westend/src/tests/snowbridge_v2_outbound.rs` (lines 277-320) already demonstrates the failure path end-to-end within the repo's own emulated-chain harness: it burns/sends a tip for a non-existent outbound nonce, and asserts (`assert!(relayer_lost_tip > 0)`) that the amount lands in `LostTips` rather than being returned to the sender.
- Failed guard checked: `system-v2::add_tip` swallows `AddTipError` and returns `Ok(())` unconditionally (lines 261-281 of `bridges/snowbridge/pallets/system-v2/src/lib.rs`), so the extrinsic always succeeds from the caller's perspective even when the tip cannot be attached.
- Deployment evidence: `snowbridge_pallet_system_frontend::Config` is wired into `asset-hub-westend` production runtime config (`cumulus/parachains/runtimes/assets/asset-hub-westend/src/bridge_to_ethereum_config.rs`), and `snowbridge_pallet_system_v2` into `bridge-hub-westend` (`cumulus/parachains/runtimes/bridge-hubs/bridge-hub-westend/src/bridge_to_ethereum_config.rs`), confirming this is live/reachable production wiring, not test-only code.
- No claim/refund extrinsic for `LostTips` was found anywhere in the repository via search, confirming the missing recovery path is real and not something I simply failed to locate elsewhere in scope.

### Citations

**File:** bridges/snowbridge/pallets/system-frontend/src/lib.rs (L340-351)
```rust
		// Build the call to dispatch the `EthereumSystem::add_tip` extrinsic on BH
		fn build_add_tip_call(
			sender: AccountIdOf<T>,
			message_id: MessageId,
			amount: u128,
		) -> BridgeHubRuntime<T> {
			BridgeHubRuntime::EthereumSystem(EthereumSystemCall::AddTip {
				sender,
				message_id,
				amount,
			})
		}
```

**File:** bridges/snowbridge/pallets/system-frontend/src/lib.rs (L372-404)
```rust
		fn swap_fee_asset_and_burn(
			origin: Location,
			fee_asset: Asset,
		) -> Result<u128, DispatchError> {
			let ether_location = T::EthereumLocation::get();
			let (fee_asset_location, fee_amount) = match fee_asset {
				Asset { id: AssetId(ref loc), fun: Fungible(amount) } => (loc, amount),
				_ => {
					tracing::debug!(target: LOG_TARGET, ?fee_asset, "error matching fee asset");
					return Err(Error::<T>::UnsupportedAsset.into());
				},
			};
			if fee_amount == 0 {
				return Ok(0);
			}

			let ether_gained = if *fee_asset_location != ether_location {
				Self::swap_and_burn(
					origin.clone(),
					fee_asset_location.clone(),
					ether_location,
					fee_amount,
				)
				.inspect_err(|&e| {
					tracing::debug!(target: LOG_TARGET, ?e, "error swapping asset");
				})?
			} else {
				burn_for_teleport::<T::AssetTransactor>(&origin, &fee_asset)
					.map_err(|_| Error::<T>::BurnError)?;
				fee_amount
			};
			Ok(ether_gained)
		}
```

**File:** bridges/snowbridge/pallets/system-v2/src/lib.rs (L136-142)
```rust
	/// Relayer reward tips that were paid by the user to incentivize the processing of their
	/// message, but then could not be added to their message reward (e.g. the nonce was already
	/// processed or their order could not be found). Capturing the lost tips here supports
	/// implementing a recovery method in the future.
	#[pallet::storage]
	pub type LostTips<T: Config> =
		StorageMap<_, Blake2_128Concat, AccountIdOf<T>, u128, ValueQuery>;
```

**File:** bridges/snowbridge/pallets/system-v2/src/lib.rs (L251-281)
```rust
		#[pallet::call_index(3)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::add_tip())]
		pub fn add_tip(
			origin: OriginFor<T>,
			sender: AccountIdOf<T>,
			message_id: MessageId,
			amount: u128,
		) -> DispatchResult {
			T::FrontendOrigin::ensure_origin(origin)?;

			let result = match message_id {
				Inbound(nonce) => <T as pallet::Config>::InboundQueue::add_tip(nonce, amount),
				Outbound(nonce) => <T as pallet::Config>::OutboundQueue::add_tip(nonce, amount),
			};

			if let Err(ref e) = result {
				tracing::debug!(target: LOG_TARGET, ?e, ?message_id, ?amount, "error adding tip");
				LostTips::<T>::mutate(&sender, |lost_tip| {
					*lost_tip = lost_tip.saturating_add(amount);
				});
			}

			Self::deposit_event(Event::<T>::TipProcessed {
				sender,
				message_id,
				amount,
				success: result.is_ok(),
			});

			Ok(())
		}
```

**File:** bridges/snowbridge/pallets/inbound-queue-v2/src/lib.rs (L248-259)
```rust
	impl<T: Config> AddTip for Pallet<T> {
		fn add_tip(nonce: u64, amount: u128) -> Result<(), AddTipError> {
			ensure!(amount > 0, AddTipError::AmountZero);
			// If the nonce is already processed, return an error
			ensure!(!Nonce::<T>::get(nonce.into()), AddTipError::NonceConsumed);
			// Otherwise add the tip.
			Tips::<T>::mutate(nonce, |tip| {
				*tip = Some(tip.unwrap_or_default().saturating_add(amount));
			});
			return Ok(());
		}
	}
```

**File:** bridges/snowbridge/pallets/outbound-queue-v2/src/lib.rs (L504-521)
```rust
	}

	impl<T: Config> AddTip for Pallet<T> {
		fn add_tip(nonce: u64, amount: u128) -> Result<(), AddTipError> {
			ensure!(amount > 0, AddTipError::AmountZero);
			PendingOrders::<T>::try_mutate_exists(nonce, |maybe_order| -> Result<(), AddTipError> {
				match maybe_order {
					Some(order) => {
						order.fee = order.fee.saturating_add(amount);
						Ok(())
					},
					None => Err(AddTipError::UnknownMessage),
				}
			})
		}
	}
}

```

**File:** cumulus/parachains/integration-tests/emulated/tests/bridges/bridge-hub-westend/src/tests/snowbridge_v2_outbound.rs (L277-320)
```rust
#[test]
pub fn tip_to_invalid_nonce_is_added_to_lost_tips() {
	fund_on_bh();
	register_assets_on_ah();
	fund_on_ah();
	set_up_eth_and_dot_pool();
	let relayer = AssetHubWestendSender::get();

	AssetHubWestend::fund_accounts(vec![(relayer.clone(), INITIAL_FUND)]);

	// A nonce that does not exist.
	let tip_message_id = MessageId::Outbound(22);

	let dot = Location::new(1, Here);
	AssetHubWestend::execute_with(|| {
		type RuntimeOrigin = <AssetHubWestend as Chain>::RuntimeOrigin;

		assert_ok!(<AssetHubWestend as AssetHubWestendPallet>::SnowbridgeSystemFrontend::add_tip(
			RuntimeOrigin::signed(relayer.clone()),
			tip_message_id.clone(),
			xcm::prelude::Asset::from((dot, 1_000_000_000u128)),
		));
	});

	BridgeHubWestend::execute_with(|| {
		type RuntimeEvent = <BridgeHubWestend as Chain>::RuntimeEvent;

		let events = BridgeHubWestend::events();
		assert!(
			events.iter().any(|event| matches!(
				event,
				RuntimeEvent::EthereumSystemV2(snowbridge_pallet_system_v2::Event::TipProcessed { sender, message_id, success, ..})
					if *sender == relayer && *message_id == tip_message_id.clone() && !(*success), // expect a failure
			)),
			"tip added event found"
		);

		let relayer_lost_tip = LostTips::<bridge_hub_westend_runtime::Runtime>::get::<
			sp_runtime::AccountId32,
		>(relayer.into());
		// Assert a tip was added to storage.
		assert!(relayer_lost_tip > 0);
	});
}
```

**File:** prdoc/stable2509/pr_9746.prdoc (L1-13)
```text
title: Snowbridge Inbound Queue V2 relayer tip payout fix

doc:
- audience: Runtime Dev
  description: |
    Fixes a bug where relayer tips were not properly paid out, causing the tips to be lost since it had already been
    burnt.

crates:
- name: snowbridge-pallet-inbound-queue-v2
  bump: patch
- name: snowbridge-test-utils
  bump: minor
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L3295-3356)
```rust
	/// Claim trapped balance for a pool member.
	///
	/// In rare scenarios, pool members may have excess held balance that is not accounted
	/// for in their pool points. This can occur when points are incorrectly dissolved
	/// without releasing the corresponding held funds.
	///
	/// If the pool has any pending slash, it will be applied to the member first before
	/// claiming the trapped balance.
	///
	/// Safe to call multiple times or for non-existent members — returns `Ok(())` as a
	/// no-op when there is nothing to do.
	pub fn do_claim_trapped_balance(member_account: &T::AccountId) -> DispatchResult {
		ensure!(
			T::StakeAdapter::strategy_type() == adapter::StakeStrategyType::Delegate,
			Error::<T>::NotSupported
		);

		// Apply any pending slash first. Ignore NothingToSlash and PoolMemberNotFound
		// (member existence is validated below).
		match Self::do_apply_slash(member_account, None, false) {
			Ok(_) => {},
			Err(e)
				if e == Error::<T>::NothingToSlash.into() ||
					e == Error::<T>::PoolMemberNotFound.into() => {},
			Err(_) => {
				return Err(Error::<T>::Defensive(DefensiveError::SlashNotApplied).into());
			},
		};

		let member = match PoolMembers::<T>::get(member_account) {
			Some(m) => m,
			None => return Ok(()),
		};

		let expected_balance = member.total_balance();
		let actual_balance =
			T::StakeAdapter::member_delegation_balance(Member::from(member_account.clone()))
				.unwrap_or_default();

		let trapped_amount = actual_balance.saturating_sub(expected_balance);

		if trapped_amount.is_zero() {
			return Ok(());
		}

		T::StakeAdapter::member_withdraw(
			Member::from(member_account.clone()),
			Pool::from(Self::generate_bonded_account(member.pool_id)),
			trapped_amount,
			0,
		)?;

		log!(
			info,
			"Claimed trapped balance for member {:?}, pool {:?}, amount {:?}",
			member_account,
			member.pool_id,
			trapped_amount
		);

		Ok(())
	}
```
