[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs (L139-173)
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
>;
```
