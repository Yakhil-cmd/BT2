### Title
`XcmRouter` for RC→AH DMP has no migration-status gating despite doc claim - (File: relay/kusama/src/xcm_config.rs, relay/polkadot/src/xcm_config.rs)

### Summary
The doc comment on `XcmRouter` in both `relay/kusama/src/xcm_config.rs` and `relay/polkadot/src/xcm_config.rs` states "This router does not route to the Asset Hub if the migration is ongoing," but the actual type is a plain `WithUniqueTopic<(ChildParachainRouter<Runtime, XcmPallet, PriceForChildParachainDelivery>,)>` with no reference to `pallet_rc_migrator::MigrationStartBlock`/`MigrationEndBlock` or any migration-aware wrapper. Additionally, `pallet_xcm::Config` for both relays sets `XcmExecuteFilter`, `XcmTeleportFilter`, and `XcmReserveTransferFilter` all to `Everything`, so no filter blocks user-initiated sends/teleports/reserve-transfers to Asset Hub during migration either.

### Finding Description
`XcmRouter` is defined as: [1](#0-0) [2](#0-1) 

This is nothing more than the standard `ChildParachainRouter` wrapped in `WithUniqueTopic`; it has no logic reading `pallet_rc_migrator::MigrationStartBlock`/`MigrationEndBlock` storage (defined at `pallets/rc-migrator/src/lib.rs:118-124`) to decide whether to deliver to `AssetHubLocation`. Grep across `pallets/rc-migrator/src/**` for suspend/halt/filter logic tied to DMP or `AssetHubLocation` returned no matches — there is no other module implementing this claimed behavior.

Furthermore, in `pallet_xcm::Config` on both relays, `type XcmExecuteFilter = Everything;`, `type XcmTeleportFilter = Everything;`, and `type XcmReserveTransferFilter = Everything;` are set without any migration-status check: [3](#0-2) 

The `Barrier` type (`TrailingSetTopicAsId<(TakeWeightCredit, AllowKnownQueryResponses<XcmPallet>, WithComputedOrigin<...>)>`) also contains no migration-aware clause: [4](#0-3) 

So a normal signed user can call `pallet_xcm::teleport_assets`/`reserve_transfer_assets`/`send` targeting `Parachain(ASSET_HUB_ID)` at any time — including while `MigrationStartBlock` is set and `MigrationEndBlock` is unset — and the message will be accepted by `SendXcmOrigin`/`ExecuteXcmOrigin` (`EnsureXcmOrigin` over `Everything`-filtered teleport/reserve-transfer paths), pass the `Barrier`, and be routed via DMP to Asset Hub exactly as in non-migration periods. Nothing in the reachable Rust code enforces "no routing to Asset Hub during migration" at the `XcmRouter` type level as the comment claims.

### Impact Explanation
If the RC-side balance migration logic in `pallet_rc_migrator` (moving/locking RC account balances to be re-created on AH) assumes that no independent value transfer to AH can occur through the ordinary XCM/DMP path during the migration window, then an unrestricted user teleport/reserve-transfer of KSM/DOT to Asset Hub during that window creates a second, unaccounted balance credit on AH for tokens that are also being migrated by `pallet_rc_migrator`'s snapshot-and-recreate process — a double-credit of KSM/DOT across RC and AH. I was not able to fully inspect the RC balance-migration extrinsics that consume `RcAccounts`/`Currency` (only the storage/config skeleton was visible in `pallets/rc-migrator/src/lib.rs`), so I cannot confirm from the available index whether the migration process re-reads live balances at the time of migration (which would make ordinary teleports harmless / self-consistent) or works off a separately-fixed snapshot (which would make them exploitable for double counting).

### Likelihood Explanation
Preconditions are attacker-independent and controlled by governance timing only (`MigrationStartBlock` set, `MigrationEndBlock` unset) — this is exactly the migration-active window described in the question. Given that preconditions hold, any signed account holding KSM/DOT can trivially call `pallet_xcm::teleport_assets` or `reserve_transfer_assets` toward `AssetHubLocation`; no privileged origin, proxy proof, or special permission is required, since `XcmTeleportFilter`/`XcmReserveTransferFilter` are `Everything`. This makes the "bypass" trivially reachable and repeatable for the duration of the migration window.

### Recommendation
- Either update the misleading doc comment on `XcmRouter` to accurately reflect that no migration gating exists at that layer, or implement the claimed behavior: wrap `ChildParachainRouter` in a `SendXcm` adapter that reads `pallet_rc_migrator::MigrationStartBlock`/`MigrationEndBlock` and rejects/queues deliveries to `AssetHubLocation` while migration is active.
- If blocking outbound routing is not actually the intended enforcement mechanism (e.g., accounting correctness is instead guaranteed by how the RC migration re-reads live balances at migration time), then the stale comment should be removed to avoid future maintainers relying on a non-existent guarantee, and the actual invariant should be verified in `pallet_rc_migrator`'s balance-migration logic and covered by tests as recommended below.

### Proof of Concept
XCM-emulator integration test:
1. Set `pallet_rc_migrator::MigrationStartBlock` to the current block (simulate migration start) and leave `MigrationEndBlock` unset.
2. As a normal signed account with a KSM/DOT balance, dispatch `pallet_xcm::teleport_assets` (or `limited_reserve_transfer_assets`) from the Relay Chain targeting `AssetHubLocation`.
3. Assert that the DMP message is actually delivered and executed on Asset Hub (i.e., `XcmRouter::deliver` succeeds and the funds land on AH) — this demonstrates the claimed "no routing to Asset Hub during migration" is not enforced.
4. Separately drive `pallet_rc_migrator`'s balance-migration path for the same account and assert whether the total KSM/DOT balance across RC+AH after both operations exceeds the account's pre-migration balance (double-accounting), or whether the migration logic already accounts for the depleted RC balance (no bug). This second assertion determines whether the confirmed missing gating is merely a stale comment or an active fund-duplication bug — I could not verify data needed for this second assertion from the indexed code and recommend a Devin session with full repository access to inspect `pallet_rc_migrator`'s balance migration extrinsics for a conclusive determination.

### Citations

**File:** relay/kusama/src/xcm_config.rs (L126-133)
```rust
/// The XCM router. When we want to send an XCM message, we use this type. It amalgamates all of our
/// individual routers.
///
/// This router does not route to the Asset Hub if the migration is ongoing.
pub(crate) type XcmRouter = WithUniqueTopic<(
	// Only one router so far - use DMP to communicate with child parachains.
	ChildParachainRouter<Runtime, XcmPallet, PriceForChildParachainDelivery>,
)>;
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

**File:** relay/kusama/src/xcm_config.rs (L298-307)
```rust
	// Anyone can execute XCM messages locally.
	type ExecuteXcmOrigin = xcm_builder::EnsureXcmOrigin<RuntimeOrigin, LocalOriginToLocation>;
	type XcmExecuteFilter = Everything;
	type XcmExecutor = xcm_executor::XcmExecutor<XcmConfig>;
	// Anyone is able to use teleportation regardless of who they are and what they want to
	// teleport.
	type XcmTeleportFilter = Everything;
	// Anyone is able to use reserve transfers regardless of who they are and what they want to
	// transfer.
	type XcmReserveTransferFilter = Everything;
```

**File:** relay/polkadot/src/xcm_config.rs (L133-140)
```rust
/// The XCM router. When we want to send an XCM message, we use this type. It amalgamates all of our
/// individual routers.
///
/// This router does not route to the Asset Hub if the migration is ongoing.
pub(crate) type XcmRouter = WithUniqueTopic<(
	// Only one router so far - use DMP to communicate with child parachains.
	ChildParachainRouter<Runtime, XcmPallet, PriceForChildParachainDelivery>,
)>;
```
