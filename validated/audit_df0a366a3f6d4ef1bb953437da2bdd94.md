No vulnerability found for this question.

**Rationale:** The original report describes an EVM/Solidity-specific gap: `ECO.sol` (L1) has pausable functionality, but `L2ECO.sol` lacks any equivalent pause modifiers on transfer/mint/burn, letting users bypass an L1 pause by depositing via the bridge into an un-paused L2 contract.

This doesn't map onto a demonstrable FRAME/Polkadot-SDK vulnerability for these reasons:

- FRAME's pause/freeze mechanisms are architecturally different from the paired-contract (L1/L2) model in the report. `pallet-tx-pause` and `pallet-safe-mode` implement pausing as a `Contains<RuntimeCall>` filter wired into `frame_system::Config::BaseCallFilter`, which is enforced uniformly at dispatch time for every call path — including calls wrapped in `pallet_utility::batch`, `pallet_proxy::proxy`, and other indirection layers, as shown by the passing tests `can_filter_balance_in_batch_when_paused` and `can_filter_balance_in_proxy_when_paused` [1](#0-0) .
- `pallet_assets::freeze_asset`/`freeze` directly flips the `AssetStatus`/`AccountStatus` on the asset itself, and `transfer`/`approve_transfer` check that status before mutating balances, as confirmed by `transferring_frozen_asset_should_not_work` [2](#0-1) . There is no separate "L2 mirror" of the asset that could be moved while the canonical asset is frozen — XCM reserve/teleport transfers for `pallet-assets`-based tokens ultimately call the same `Assets` mutate functions, so a freeze is not bypassable through a bridge/XCM path the way L2ECO could bypass ECO.sol's pause via the L1↔L2 bridge.
- `xcm-executor`'s `Transact` instruction is gated by `Config::SafeCallFilter` [3](#0-2) , but this is a distinct, narrower mechanism (whitelisting recursive calls) rather than a "does the destination chain also enforce the pause" problem; no evidence was found of a chain where one side of a bridged/teleported asset enforces a freeze/pause and the other side does not.

No FRAME pallet, XCM configuration, or bridge module in this codebase exhibits the asymmetric "paused on one layer, unpaused on the paired layer, exploitable via bridge deposit" pattern described in the report, and the scan guidance requires a demonstrable Polkadot-SDK analog rather than a generic feature-parity observation.

### Citations

**File:** substrate/frame/tx-pause/src/tests.rs (L87-127)
```rust
#[test]
fn can_filter_balance_in_batch_when_paused() {
	new_test_ext().execute_with(|| {
		let batch_call =
			RuntimeCall::Utility(pallet_utility::Call::batch { calls: vec![call_transfer(1, 1)] });

		assert_ok!(TxPause::pause(
			RuntimeOrigin::signed(mock::PauseOrigin::get()),
			full_name::<Test>(b"Balances", b"transfer_allow_death"),
		));

		assert_ok!(batch_call.clone().dispatch(RuntimeOrigin::signed(0)));
		System::assert_last_event(
			pallet_utility::Event::BatchInterrupted {
				index: 0,
				error: frame_system::Error::<Test>::CallFiltered.into(),
			}
			.into(),
		);
	});
}

#[test]
fn can_filter_balance_in_proxy_when_paused() {
	new_test_ext().execute_with(|| {
		assert_ok!(TxPause::pause(
			RuntimeOrigin::signed(mock::PauseOrigin::get()),
			full_name::<Test>(b"Balances", b"transfer_allow_death"),
		));

		assert_ok!(Proxy::add_proxy(RuntimeOrigin::signed(1), 2, ProxyType::JustTransfer, 0));

		assert_ok!(Proxy::proxy(RuntimeOrigin::signed(2), 1, None, Box::new(call_transfer(1, 1))));
		System::assert_last_event(
			pallet_proxy::Event::ProxyExecuted {
				result: DispatchError::from(frame_system::Error::<Test>::CallFiltered).into(),
			}
			.into(),
		);
	});
}
```

**File:** substrate/frame/assets/src/tests.rs (L818-832)
```rust
#[test]
fn transferring_frozen_asset_should_not_work() {
	build_and_execute(|| {
		assert_ok!(Assets::force_create(RuntimeOrigin::root(), 0, 1, true, 1));
		assert_ok!(Assets::mint(RuntimeOrigin::signed(1), 0, 1, 100));
		assert_eq!(Assets::balance(0, 1), 100);
		assert_ok!(Assets::freeze_asset(RuntimeOrigin::signed(1), 0));
		assert_noop!(
			Assets::transfer(RuntimeOrigin::signed(1), 0, 2, 50),
			Error::<Test>::AssetNotLive
		);
		assert_ok!(Assets::thaw_asset(RuntimeOrigin::signed(1), 0));
		assert_ok!(Assets::transfer(RuntimeOrigin::signed(1), 0, 2, 50));
	});
}
```

**File:** polkadot/xcm/xcm-executor/src/lib.rs (L1096-1103)
```rust
				if !Config::SafeCallFilter::contains(&message_call) {
					tracing::trace!(
						target: "xcm::process_instruction::transact",
						"Call filtered by `SafeCallFilter`",
					);

					return Err(XcmError::NoPermission)
				}
```
