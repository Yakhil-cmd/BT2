### Title
`DenyReserveTransferToRelayChain` in bridge-hub-kusama's `Barrier` is non-recursive, allowing a nested reserve-withdraw-to-Relay-Chain instruction to bypass the deny filter - (File: `system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs`)

### Summary
Bridge-hub-kusama's `Barrier` wraps `DenyReserveTransferToRelayChain` directly (non-recursive), whereas bridge-hub-polkadot and bulletin-polkadot wrap the same filter in `DenyRecursively<..>`. Since `DenyThenTry`'s deny filter is invoked only once against the top-level instruction list, an attacker can nest a reserve-transfer-to-Relay-Chain instruction (e.g. inside `SetAppendix`/`SetErrorHandler`) so it is never inspected, and it will still execute in the same XCM-executor context after the outer, allowed instructions complete.

### Finding Description
The bridge-hub-kusama barrier is defined as: [1](#0-0) 

Compare this to bridge-hub-polkadot, which explicitly wraps the same deny rule in `DenyRecursively`: [2](#0-1) 

and bulletin-polkadot, which does the same: [3](#0-2) 

`DenyReserveTransferToRelayChain` (from `xcm-builder`) inspects only the top-level instruction sequence of the message handed to `Barrier::should_execute`. `DenyRecursively` was introduced specifically to also walk into nested `Xcm` programs carried by instructions such as `SetAppendix` and `SetErrorHandler`, whose sub-programs are executed later by the same `XcmExecutor` call without a second pass through the `Barrier`. Because bridge-hub-kusama uses the plain (non-recursive) `DenyReserveTransferToRelayChain`, a message whose *top-level* instructions look benign (e.g. `WithdrawAsset` + `BuyExecution`, satisfying `AllowTopLevelPaidExecutionFrom<Everything>`) but whose `SetAppendix` carries `InitiateReserveWithdraw`/`DepositReserveAsset` targeting `RelayChainLocation` will pass the barrier, and the nested reserve-withdraw will still run when the appendix executes.

The instruction that performs the withdrawal (`InitiateReserveWithdraw`) does not itself consult `Config::IsReserve`; it only takes assets already in the holding register (funded via a prior `WithdrawAsset` against the local `FungibleTransactor`/`Balances`) and forwards them to the `reserve` location. Bridge-hub-kusama's `IsReserve = ()` is irrelevant to this outbound path, so it does not provide a secondary safeguard: [4](#0-3) 

An attacker who is a normal signed account holding KSM on bridge-hub-kusama can submit such a message via `pallet_xcm::execute` (local origin, self-authored `Xcm`), since the entry point does not require any privilege beyond a signed origin and sufficient balance to pay execution fees.

### Impact Explanation
An unprivileged, signed user can perform a reserve-transfer of KSM from bridge-hub-kusama to the Relay Chain despite this route being explicitly denied by design (bridge-hub is documented as not recognizing any reserve location and instead requiring teleports). This subverts the intended asset-accounting model between bridge-hub-kusama and the Relay Chain, and diverges from the parallel-chain (bridge-hub-polkadot) protection that was hardened with `DenyRecursively`.

### Likelihood Explanation
Feasibility is high: the attacker needs only (1) a signed account with a KSM balance on bridge-hub-kusama (obtainable via ordinary teleport from the Relay Chain/Asset Hub) and (2) the ability to call `pallet_xcm::execute` with a crafted `Xcm` program — both are ordinary, permission-less user actions. The exploit is deterministic and repeatable each time such a message is submitted, since the barrier logic is static configuration, not privileged/gated behavior.

### Recommendation
Wrap `DenyReserveTransferToRelayChain` in `DenyRecursively` in bridge-hub-kusama's `Barrier`, mirroring bridge-hub-polkadot:
```rust
pub type Barrier = TrailingSetTopicAsId<
    DenyThenTry<
        DenyRecursively<DenyReserveTransferToRelayChain>,
        ( ... )
    >,
>;
```
at `system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs:139-172`.

### Proof of Concept
xcm-emulator test (bridge-hub-kusama), analogous to existing `reserve_transfer_ksm_from_asset_hub_to_relay_fails`:
1. Fund a signed test account on `BridgeHubKusama` with KSM.
2. Build an `Xcm` program executed via `PolkadotXcm::execute` with a top-level `WithdrawAsset`+`BuyExecution` (passes `AllowTopLevelPaidExecutionFrom<Everything>`), followed by `SetAppendix(Xcm(vec![InitiateReserveWithdraw { assets: Wild(All), reserve: RelayChainLocation::get(), xcm: Xcm(vec![DepositAsset { assets: Wild(All), beneficiary: <relay account> }]) }]))`.
3. Execute on `BridgeHubKusama` and assert:
   - The call succeeds (not filtered) — contrasting with the expected `Filtered` error that occurs when `InitiateReserveWithdraw` is placed at the top level.
   - A message queued for the Relay Chain (`UMP`/HRMP outbound) containing the withdrawn KSM is observed, and/or the Relay Chain receiver's balance increases after `Kusama::execute_with`.
4. Repeat the same test against `BridgeHubPolkadot` and assert the nested message is rejected (since `DenyRecursively` inspects `SetAppendix` contents), demonstrating the behavioral divergence between the two runtimes.

### Citations

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs (L139-172)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyReserveTransferToRelayChain,
		(
			// Allow local users to buy weight credit.
			TakeWeightCredit,
			// Expected responses are OK.
			AllowKnownQueryResponses<PolkadotXcm>,
			WithComputedOrigin<
				(
					// If the message is one that immediately attempts to pay for execution, then
					// allow it.
					AllowTopLevelPaidExecutionFrom<Everything>,
					// Parent and its pluralities (i.e. governance bodies) and relay treasury get
					// free execution.
					AllowExplicitUnpaidExecutionFrom<
						(
							ParentOrParentsPlurality,
							Equals<RelayTreasuryLocation>,
							Equals<AssetHubLocation>,
							AssetHubPlurality,
						),
						TrustedAliasers,
					>,
					// Subscriptions for version tracking are OK.
					AllowSubscriptionsFrom<ParentRelayOrSiblingParachains>,
					// HRMP notifications from the relay chain are OK.
					AllowHrmpNotificationsFromRelayChain,
				),
				UniversalLocation,
				ConstU32<8>,
			>,
		),
	>,
```

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs (L198-205)
```rust
	type AssetTransactor = FungibleTransactor;
	type OriginConverter = XcmOriginToTransactDispatchOrigin;
	// BridgeHub does not recognize a reserve location for any asset. Users must teleport KSM
	// where allowed (e.g. with the Relay Chain).
	type IsReserve = ();
	type IsTeleporter = TrustedTeleporters;
	type UniversalLocation = UniversalLocation;
	type Barrier = Barrier;
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

**File:** system-parachains/bulletin/bulletin-polkadot/src/xcm_config.rs (L147-149)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyRecursively<DenyReserveTransferToRelayChain>,
```
