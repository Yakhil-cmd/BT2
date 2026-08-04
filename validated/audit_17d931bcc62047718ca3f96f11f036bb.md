### Title
DenyReserveTransferToRelayChain is not applied recursively on Asset Hub, allowing bypass via `SetAppendix`/`ExecuteWithOrigin`-nested reserve-transfer instructions - (File: system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs, system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs)

### Summary
Asset Hub's `Barrier` wraps the deny-filter as bare `DenyReserveTransferToRelayChain`, while `bridge-hub-polkadot` and `bulletin-polkadot` wrap the same filter as `DenyRecursively<DenyReserveTransferToRelayChain>`. Because `DenyReserveTransferToRelayChain::should_execute` only pattern-matches the flat top-level instruction slice passed to the executor's `Barrier` check, a reserve-transfer-to-relay instruction placed inside a locally re-executed nested program (`SetAppendix`/`SetErrorHandler`/`ExecuteWithOrigin`) is never inspected and is not re-checked by the executor when it later runs that nested program.

### Finding Description
The Asset Hub `Barrier` type is defined as: [1](#0-0) [2](#0-1) 

Compare this with `bridge-hub-polkadot`, which wraps the identical filter with `DenyRecursively`: [3](#0-2) 

`DenyReserveTransferToRelayChain` (from the upstream `xcm-builder` crate, not defined in this repo) scans the top-level `&mut [Instruction]` slice for `InitiateReserveWithdraw`/`DepositReserveAsset`/`TransferReserveAsset` targeting the Relay Chain. The XCM executor invokes this `Barrier::should_execute` check only once, at the start of processing the outer message. Nested programs embedded in `SetAppendix`, `SetErrorHandler`, or `ExecuteWithOrigin` are executed by the executor's internal recursive `process()` call *without* re-invoking the top-level `Barrier`. `DenyRecursively<T>` was introduced upstream precisely to close this gap by walking into these locally-executed nested XCM fields and re-applying `T`'s deny check; chains that use the bare filter (not `DenyRecursively`-wrapped) do not get this protection.

Exploit flow on Asset Hub (Kusama/Polkadot):
1. Attacker (any signed account) calls `PolkadotXcm::execute` with a top-level program whose flat instruction list does **not** directly contain a denied instruction (e.g., `WithdrawAsset`, `SetAppendix(Xcm(vec![InitiateReserveWithdraw{reserve: Parent, ..}]))`, `DepositAsset{..}`).
2. `DenyReserveTransferToRelayChain::should_execute` scans only the outer instruction list, finds no `InitiateReserveWithdraw`/`DepositReserveAsset`/`TransferReserveAsset` at that level, and returns `Ok(())`.
3. The rest of the `Barrier` tuple (`TakeWeightCredit`, `WithComputedOrigin<AllowTopLevelPaidExecutionFrom<Everything>, ..>`) passes for a normally-paid signed-origin execution.
4. The executor runs the main program, then executes the `SetAppendix` payload locally (or `ExecuteWithOrigin`'s inner program), which contains the previously-denied `InitiateReserveWithdraw{reserve: Parent, ..}` instruction — this is never re-checked against the `Barrier`.

### Impact Explanation
If the underlying accounting for the reserve-withdraw-to-relay path is asymmetric (which is the entire reason the explicit deny rule exists — DOT/KSM on Asset Hub is not backed by a spendable "reserve" held on the Relay Chain the way ordinary reserve-asset transfers work), successfully executing this instruction lets an attacker move/duplicate value between Asset Hub and the Relay Chain outside the intended teleport-only path, breaking the asset-hub-only reserve invariant for the native token.

### Likelihood Explanation
Precondition matches the audit's stated precondition exactly: an unprivileged, signed account can call `PolkadotXcm::execute` and craft arbitrary XCM v5 programs, including `SetAppendix`/`ExecuteWithOrigin` with nested reserve-transfer instructions, at no special privilege. The gap is structural (missing `DenyRecursively` wrapper) and deterministic, not probabilistic, and is repeatable on every execution.

### Recommendation
Wrap `DenyReserveTransferToRelayChain` with `DenyRecursively` in the `Barrier` definitions for `asset-hub-kusama` and `asset-hub-polkadot` (and audit the other system chains — `bridge-hub-kusama`, `collectives-polkadot`, `coretime-kusama`, `coretime-polkadot`, `encointer`, `people-kusama`, `people-polkadot` — which show the same bare, non-recursive usage), matching the pattern already used in `bridge-hub-polkadot` and `bulletin-polkadot`:
```rust
DenyThenTry<
    DenyRecursively<DenyReserveTransferToRelayChain>,
    ( ... )
>
```

### Proof of Concept
xcm-emulator/unit test plan (Asset Hub Kusama/Polkadot):
```rust
#[test]
fn reserve_transfer_to_relay_via_nested_appendix_is_still_denied() {
    let signed_origin = <AssetHubKusama as Chain>::RuntimeOrigin::signed(AssetHubKusamaSender::get());
    let ksm_location = KsmLocation::get();
    let amount = ASSET_HUB_KUSAMA_ED * 1000;

    AssetHubKusama::execute_with(|| {
        // Nest the denied instruction inside SetAppendix so the flat
        // DenyReserveTransferToRelayChain scan does not see it directly.
        let xcm: Xcm<asset_hub_kusama_runtime::RuntimeCall> = Xcm(vec![
            WithdrawAsset((ksm_location.clone(), amount).into()),
            SetAppendix(Xcm(vec![
                InitiateReserveWithdraw {
                    assets: Wild(All),
                    reserve: Location::parent(),
                    xcm: Xcm::new(),
                },
            ])),
            DepositAsset { assets: Wild(All), beneficiary: signed_origin_account_location() },
        ]);
        let result = <AssetHubKusama as AssetHubKusamaPallet>::PolkadotXcm::execute(
            signed_origin,
            bx!(VersionedXcm::V5(xcm)),
            Weight::MAX,
        );
        // EXPECTED (fixed): rejected/filtered, same as the direct top-level case.
        // ACTUAL (bug, pre-fix): executes successfully, and a reserve-withdraw
        // message is forwarded to the Relay Chain.
        assert!(result.is_err(), "nested reserve-transfer-to-relay must be denied");
    });
}
```
Assertions: (1) the direct top-level `InitiateReserveWithdraw{reserve: Parent}` is denied (already covered by existing `reserve_transfer_ksm_from_asset_hub_to_relay_fails`-style tests, e.g. [4](#0-3) ); (2) the same instruction nested inside `SetAppendix`/`ExecuteWithOrigin` must also be denied — currently it is not, on chains lacking `DenyRecursively`.

### Citations

**File:** system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs (L270-273)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyReserveTransferToRelayChain,
		(
```

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs (L374-377)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyReserveTransferToRelayChain,
		(
```

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs (L150-160)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		(
			DenyRecursively<DenyReserveTransferToRelayChain>,
			DenyRecursively<
				DenyExportMessageFrom<
					EverythingBut<Equals<AssetHubLocation>>,
					Equals<EthereumNetwork>,
				>,
			>,
		),
```

**File:** integration-tests/emulated/tests/assets/asset-hub-kusama/src/tests/reserve_transfer.rs (L561-596)
```rust
/// Reserve Transfers of KSM from Asset Hub to Relay Chain shouldn't work
#[test]
fn reserve_transfer_ksm_from_asset_hub_to_relay_fails() {
	// Init values for Asset Hub
	let signed_origin =
		<AssetHubKusama as Chain>::RuntimeOrigin::signed(AssetHubKusamaSender::get());
	let destination = AssetHubKusama::parent_location();
	let beneficiary_id = KusamaReceiver::get();
	let beneficiary: Location =
		AccountId32Junction { network: None, id: beneficiary_id.into() }.into();
	let amount_to_send: Balance = ASSET_HUB_KUSAMA_ED * 1000;

	let assets: Assets = (Parent, amount_to_send).into();
	let fee_asset_item = 0;

	// this should fail
	AssetHubKusama::execute_with(|| {
		let result =
			<AssetHubKusama as AssetHubKusamaPallet>::PolkadotXcm::limited_reserve_transfer_assets(
				signed_origin,
				bx!(destination.into()),
				bx!(beneficiary.into()),
				bx!(assets.into()),
				fee_asset_item,
				WeightLimit::Unlimited,
			);
		assert_err!(
			result,
			DispatchError::Module(sp_runtime::ModuleError {
				index: 31,
				error: [2, 0, 0, 0],
				message: Some("Filtered")
			})
		);
	});
}
```
