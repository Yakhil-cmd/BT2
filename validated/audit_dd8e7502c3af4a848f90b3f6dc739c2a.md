### Title
Unauthorized privileged EthereumSystemV2 calls via forged `AllowFromEthereumFrontend` origin using `DescendOrigin` - ([File: system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs])

### Summary
`AllowFromEthereumFrontend::contains` only pattern-matches on the *shape* of a `Location` — `(1, [Parachain(ASSET_HUB_ID), PalletInstance(SystemFrontendPalletInstance)])` — with no cryptographic or dispatch-path verification that the message truly originated from `snowbridge_pallet_system_frontend`'s own code path. Because `DescendOrigin` is a normal, unprivileged XCM instruction that lets any XCM program executing on behalf of a chain claim to be any interior junction of that chain, a message routed to Bridge Hub whose leading instructions descend into `PalletInstance(SystemFrontendPalletInstance)` will be accepted by `EnsureXcm<AllowFromEthereumFrontend>` as the legitimate frontend, regardless of who actually built the message.

### Finding Description
`AllowFromEthereumFrontend` is defined purely as a location-shape check: [1](#0-0) 

This is used as `FrontendOrigin` for `snowbridge_pallet_system_v2::Config`, which gates the privileged register-token / set-parameters entry points. Structurally identical filters elsewhere in this codebase (e.g. `AllowSiblingsOnly`) show that these `Contains<Location>` checks are only ever shape-based, and the codebase's own test suite demonstrates that `DescendOrigin` is the standard, unrestricted mechanism by which a chain's outbound message legitimately claims to be "from pallet X inside me" — see the Collectives `Architects`-origin test where `pallet_xcm::send` auto-prepends `DescendOrigin` to let a caller impersonate a specific pallet location on a sibling chain [2](#0-1) , and the Encointer treasury payout code, which explicitly builds `DescendOrigin(from_location.interior.clone())` as an arbitrary, caller-supplied origin claim inside a cross-chain XCM program [3](#0-2) .

Bridge Hub's `Barrier` for incoming HRMP messages is a `WithComputedOrigin<..., UniversalLocation, ConstU32<8>>` wrapper (same pattern seen relay-wide, e.g. [4](#0-3) ), which pre-scans leading `DescendOrigin`/`ClearOrigin`/`UniversalOrigin` instructions to compute an effective origin *before* applying the barrier's allow-rules (commonly `AllowTopLevelPaidExecutionFrom<Everything>`), meaning a paid program from any sender is generally allowed to execute — the barrier does not itself validate that the descended pallet-instance claim is legitimate; that responsibility falls entirely on `AllowFromEthereumFrontend`'s shape check, which does not verify provenance.

The attack surface is: a message legitimately transported via HRMP from Asset Hub (para 1000, whose sending para-id is faithfully attested by Cumulus HRMP/XCMP transport — this part cannot be spoofed) can carry, as its first instructions on Bridge Hub, `DescendOrigin(PalletInstance(SystemFrontendPalletInstance))` followed by `Transact(EthereumSystemV2::register_token/set_parameters)`. Once executed, the XCM executor's origin register becomes exactly `(1, [Parachain(1000), PalletInstance(36)])`, and `Transact`'s `OriginConverter` (`EnsureXcm<AllowFromEthereumFrontend>`) accepts it, dispatching the privileged call with the `FrontendOrigin`, bypassing the frontend pallet's own `RegisterTokenOrigin`/asset-ownership checks entirely (those checks only apply on the Asset Hub side, inside `snowbridge_pallet_system_frontend`'s real extrinsics — not to hand-crafted `Transact` programs delivered straight to Bridge Hub).

**Unresolved verification gap:** the outbound path for an ordinary signed user to place such an attacker-chosen program with a leading `DescendOrigin(PalletInstance(36))` onto the actual AssetHub→BridgeHub HRMP channel requires either (a) `pallet_xcm::send`, which auto-inserts `DescendOrigin(interior-of-caller)` derived from `LocalOriginToLocation` — for ordinary signed accounts this is an `AccountId32` junction, not `PalletInstance`, so this specific path taints the origin with an extra junction and would *not* produce an exact 2-junction match; or (b) `pallet_xcm::execute` with an instruction such as `InitiateTransfer`/`DepositReserveAsset` whose `remote_xcm` field is fully attacker-specified content forwarded to Bridge Hub without any origin-tainting wrapper. I was not able to confirm, within the available tool budget, Asset Hub Polkadot's exact `XcmExecuteFilter`/`SafeCallFilter` configuration that governs whether ordinary signed users may invoke `pallet_xcm::execute` with such forwarding instructions. This is the deciding factor for real-world exploitability and should be checked directly (`asset-hub-polkadot/src/xcm_config.rs`, `impl pallet_xcm::Config for Runtime`).

### Impact Explanation
If path (b) above is permitted for ordinary users, an unprivileged account could register arbitrary Ethereum-side tokens or mutate Snowbridge V2 system parameters without going through the intended `RegisterTokenOrigin` asset-ownership checks or governance, corresponding exactly to the scoped impact (unauthorized privileged call execution bypassing `RegisterTokenOrigin`).

### Likelihood Explanation
Feasibility hinges entirely on whether Asset Hub's local XCM-execute path allows a signed user to forward an attacker-controlled `remote_xcm` (containing `DescendOrigin`) to a sibling chain without going through `pallet_xcm::send`'s origin-tainting wrapper. This needs direct confirmation of `XcmExecuteFilter`/`SafeCallFilter` in `asset-hub-polkadot`'s runtime config, which could not be completed in this pass.

### Recommendation
Do not rely solely on `Location` shape-matching for privileged cross-chain origins. Either (a) restrict/deny `pallet_xcm::execute` instructions capable of forwarding attacker-defined `remote_xcm` content to Bridge Hub from ordinary accounts via `SafeCallFilter`/`XcmExecuteFilter`, or (b) have `snowbridge_pallet_system_frontend` sign/tag its legitimate outbound messages (e.g. via a `SetTopic`/nonce scheme validated on Bridge Hub, or by requiring the message be wrapped via a queue/router only reachable from the pallet's own dispatch code) so `AllowFromEthereumFrontend` verifies genuine pallet-originated dispatch rather than a replicated `Location` pattern.

### Proof of Concept
xcm-emulator test on Bridge Hub Polkadot:
1. From Asset Hub, as a plain signed (non-privileged) account, call `PolkadotXcm::execute` with a program containing `WithdrawAsset`/`PayFees` plus `InitiateTransfer { destination: BridgeHub, preserve_origin: true, remote_xcm: Xcm([DescendOrigin(PalletInstance(SystemFrontendPalletInstance::get())), Transact { call: EthereumSystemV2::register_token(...).encode() }, ExpectTransactStatus(Success)]) }`.
2. Assert on Bridge Hub that `EthereumSystemV2::RegisterToken` event fires despite the caller never invoking the real `snowbridge_pallet_system_frontend::register_token` extrinsic and never satisfying `RegisterTokenOrigin`.
3. Negative control: same test but confirm rejection if `XcmExecuteFilter`/`SafeCallFilter` blocks the forwarding instruction — this determines whether the bug is reachable in practice.

### Citations

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs (L292-313)
```rust
pub struct AllowFromEthereumFrontend;
impl Contains<Location> for AllowFromEthereumFrontend {
	fn contains(location: &Location) -> bool {
		match location.unpack() {
			(1, [Parachain(para_id), PalletInstance(index)]) =>
				*para_id == polkadot_runtime_constants::system_parachain::ASSET_HUB_ID &&
					*index == SystemFrontendPalletInstance::get(),
			_ => false,
		}
	}
}

impl snowbridge_pallet_system_v2::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OutboundQueue = EthereumOutboundQueueV2;
	type InboundQueue = EthereumInboundQueueV2;
	type FrontendOrigin = EnsureXcm<AllowFromEthereumFrontend>;
	type WeightInfo = crate::weights::snowbridge_pallet_system_v2::WeightInfo<Runtime>;
	type GovernanceOrigin = EnsureRootWithSuccess<crate::AccountId, RootLocation>;
	#[cfg(feature = "runtime-benchmarks")]
	type Helper = ();
}
```

**File:** integration-tests/emulated/tests/assets/asset-hub-polkadot/src/tests/aliases.rs (L600-648)
```rust
/// Helper: sends an XCM from Collectives with the Architects origin to Asset Hub.
/// The message aliases into the Fellowship pallet at `pallet_index`, withdraws DOT from the
/// pallet's sovereign account, and deposits it to a beneficiary.
///
/// This uses `PolkadotXcm::send` on the Collectives chain with the Architects origin, which
/// auto-prepends `DescendOrigin` via `ArchitectsToLocation`. Asset Hub then processes the
/// message: the origin descends to the Architects location, aliases into the target pallet,
/// and performs the transfer.
///
/// Only works for the `FellowshipTreasury` and `FellowshipSalary` pallet instances.
fn architects_alias_into_fellowship_pallet(pallet_index: u8) {
	let collectives_para_id: u32 = CollectivesPolkadot::para_id().into();
	let amount: Balance = POLKADOT_ED * 100;

	// The Fellowship pallet location (treasury or salary) on Collectives, as seen from AH.
	let pallet_location =
		Location::new(1, [Parachain(collectives_para_id), PalletInstance(pallet_index)]);

	// Compute the sovereign account for this pallet location on AH.
	let pallet_sovereign =
		asset_hub_polkadot_runtime::xcm_config::LocationToAccountId::convert_location(
			&pallet_location,
		)
		.expect("Failed to convert pallet location to account");

	let beneficiary: AccountId = [42u8; 32].into();

	// Fund the pallet's sovereign account on AH.
	AssetHubPolkadot::fund_accounts(vec![(pallet_sovereign.clone(), amount * 2)]);

	// Record pre-balances on AH.
	let (pre_sovereign_balance, pre_beneficiary_balance) = AssetHubPolkadot::execute_with(|| {
		type Balances = <AssetHubPolkadot as AssetHubPolkadotPallet>::Balances;
		(
			<Balances as Inspect<_>>::balance(&pallet_sovereign),
			<Balances as Inspect<_>>::balance(&beneficiary),
		)
	});

	// Send XCM from Collectives with the Architects origin.
	// pallet_xcm::send auto-prepends DescendOrigin based on ArchitectsToLocation, which
	// converts Architects to [Plurality { Technical, Voice }, GeneralIndex(ARCHITECTS_RANK)].
	// After DescendOrigin, the executor origin on AH becomes:
	//   (1, [Parachain(1001), Plurality { Technical, Voice }, GeneralIndex(ARCHITECTS_RANK)])
	//
	// The message then:
	// 1. UnpaidExecution — allowed because the computed origin matches FellowshipEntities
	// 2. AliasOrigin — FellowshipArchitectsAlias allows Architects → treasury/salary
	// 3. WithdrawAsset — withdraws DOT from the aliased pallet's sovereign account
```

**File:** system-parachains/encointer/src/treasuries_xcm_payout.rs (L263-278)
```rust
	// Transform `from` into Location::new(1, XX([Parachain(source), from.interior }])
	// We need this one for the refunds.
	let from_at_target = append_from_to_target(from_location.clone(), destination.clone())?;

	let xcm = Xcm(vec![
		// Transform origin into Location::new(1, X2([Parachain(SourceParaId), from.interior }])
		DescendOrigin(from_location.interior.clone()),
		// For simplicity, we assume now that the treasury has KSM and pays fees with KSM.
		WithdrawAsset(vec![remote_fee.clone()].into()),
		PayFees { asset: remote_fee },
		SetAppendix(Xcm(vec![
			RefundSurplus,
			DepositAsset { assets: AssetFilter::Wild(WildAsset::All), beneficiary: from_at_target },
		])),
		TransferAsset { beneficiary, assets: (asset_id, amount).into() },
	]);
```

**File:** relay/kusama/src/xcm_config.rs (L180-198)
```rust
/// The barriers one of which must be passed for an XCM message to be executed.
pub type Barrier = TrailingSetTopicAsId<(
	// Weight that is paid for may be consumed.
	TakeWeightCredit,
	// Expected responses are OK.
	AllowKnownQueryResponses<XcmPallet>,
	WithComputedOrigin<
		(
			// If the message is one that immediately attempts to pay for execution, then allow it.
			AllowTopLevelPaidExecutionFrom<Everything>,
			// Messages coming from system parachains need not pay for execution.
			AllowExplicitUnpaidExecutionFrom<(IsChildSystemParachain<ParaId>, AssetHubPlurality)>,
			// Subscriptions for version tracking are OK.
			AllowSubscriptionsFrom<OnlyParachains>,
		),
		UniversalLocation,
		ConstU32<8>,
	>,
)>;
```
