No vulnerability found for this question.

The original report describes a deployment/configuration gap — a missing Chainlink `rETH/USD` price feed on a specific external chain (Base) — not an exploitable code-level flaw. In `polkadot-sdk--009`, the closest conceptual analog is `pallet-oracle` [1](#0-0) , which is a self-contained, permissioned push-oracle where trusted operators submit `(OracleKey, OracleValue)` pairs directly on-chain via `feed_values` [2](#0-1) , rather than depending on an external third-party data feed (like Chainlink) that may or may not exist on a given deployment network. Because `OracleKey`/`OracleValue` are fully generic and configured per-runtime (e.g. `u32`/`u128` in the kitchensink runtime) [3](#0-2) , there is no analogous "the required external feed doesn't exist on this chain" failure mode baked into the pallet's logic.

Additionally, checking the one consumer that resembles a stablecoin/price-dependent module, `pallet-psm` (Peg Stability Module), it performs fixed 1:1 (decimal-adjusted) swaps between an internal and external asset and does not consult `pallet-oracle` or any price feed at all [4](#0-3) , so there's no code path where a missing/absent price feed would cause an unhandled revert or produce an incorrect price, unlike the `OracleModule.sol` scenario in the original report.

The underlying issue in the report is a network/deployment-configuration problem (a specific data feed not being deployed on a specific chain) rather than a demonstrable logic flaw reachable by an unprivileged user through a real extrinsic, contract call, or XCM message — this falls squarely under the excluded "config-only/dependency-only findings" category, and no comparable exploitable analog exists in the reviewed FRAME code.

### Citations

**File:** substrate/frame/honzon/oracle/src/lib.rs (L18-21)
```rust
//! # Oracle
//!
//! A pallet that provides a decentralized and trustworthy way to bring external, off-chain data
//! onto the blockchain.
```

**File:** substrate/frame/honzon/oracle/src/lib.rs (L357-377)
```rust
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::feed_values(values.len() as u32))]
		pub fn feed_values(
			origin: OriginFor<T>,
			values: BoundedVec<(T::OracleKey, T::OracleValue), T::MaxFeedValues>,
		) -> DispatchResultWithPostInfo {
			let feeder = ensure_signed_or_root(origin.clone())?;

			let who = Self::ensure_account(feeder)?;

			// ensure account hasn't dispatched an updated yet
			<HasDispatched<T, I>>::try_mutate(|set| {
				set.try_insert(who.clone())
					.map_err(|_| Error::<T, I>::ExceedsMaxHasDispatchedSize)?
					.then_some(())
					.ok_or(Error::<T, I>::AlreadyFeeded)
			})?;

			Self::do_feed_values(who, values.into());
			Ok(Pays::No.into())
		}
```

**File:** substrate/bin/node/runtime/src/lib.rs (L3180-3193)
```rust
impl pallet_oracle::Config for Runtime {
	type OnNewData = ();
	type CombineData = pallet_oracle::DefaultCombineData<Self, ConstU32<5>, ConstU64<3600>>;
	type Time = Timestamp;
	type OracleKey = u32;
	type OracleValue = u128;
	type PalletId = OraclePalletId;
	type Members = TechnicalMembership;
	type WeightInfo = ();
	type MaxHasDispatchedSize = OracleMaxHasDispatchedSize;
	type MaxFeedValues = OracleMaxFeedValues;
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = OracleBenchmarkingHelper;
}
```

**File:** substrate/frame/psm/README.md (L39-63)
```markdown
## Swap Lifecycle

### 1. Mint (External → Internal)

```rust
mint(origin, internal_asset, asset_id, external_amount)
```

- Deposits `external_amount` of `asset_id` into `internal_asset`'s PSM reserve
- Mints `internal_asset` to the user (minus minting fee)
- Fee is minted as `internal_asset` and transferred to the instance's `fee_destination`
- Enforces the per-instance aggregate `max_debt` and the per-external normalised ceiling
- Requires the swap (in internal units) to be `>= PsmInfo::min_swap_amount`

### 2. Redeem (Internal → External)

```rust
redeem(origin, internal_asset, asset_id, amount)
```

- Burns `amount` of `internal_asset` from the user
- Transfers external asset from the instance's reserve to the user
- Redemption fee is transferred from the user as `internal_asset` to `fee_destination`
- Limited by the per-external tracked debt (`PsmDebt`), not raw reserve balance
- Requires `amount >= PsmInfo::min_swap_amount`
```
