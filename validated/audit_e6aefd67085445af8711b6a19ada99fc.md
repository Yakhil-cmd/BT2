## Analog Found: Non-UTF8 Asset Metadata Causes Guaranteed Revert in `pallet-assets` ERC20 Precompile

### Title
`pallet-assets` precompile `name()`/`symbol()` unconditionally revert for assets whose metadata is not valid UTF-8 - (File: `substrate/frame/assets/precompiles/src/lib.rs`)

### Summary
The Teller report's root cause is an EVM contract assuming `symbol()` always returns a `string`, when the ERC20 standard leaves the encoding optional (e.g. MKR returns `bytes32`), causing ABI-decoding to revert for the caller. The Polkadot SDK analog is the inverse but structurally identical assumption inside `pallet-assets-precompiles`: it implements `IERC20Metadata.name()`/`symbol()` by reading raw `Vec<u8>` from `pallet-assets` storage and force-decoding it as UTF-8 with `String::from_utf8`, reverting the call if the bytes aren't valid UTF-8 [1](#0-0) . Nothing in `pallet-assets` guarantees the stored `name`/`symbol` bytes are valid UTF-8.

### Finding Description
`pallet_assets::Pallet::do_set_metadata` only enforces a length bound via `T::StringLimit` when converting the caller-supplied `name`/`symbol` `Vec<u8>` into `BoundedVec<u8, T::StringLimit>` — there is no UTF-8 validation at all [2](#0-1) . This function is reachable through the signed, permissioned-but-not-privileged `set_metadata` extrinsic, callable by any asset owner (not root, not governance) [3](#0-2) , and also through `force_set_metadata` under `ForceOrigin` [4](#0-3) . The underlying storage type `AssetMetadata` stores `name`/`symbol` as an unconstrained `BoundedString` with no encoding guarantee [5](#0-4) .

The `pallet-assets-precompiles` crate (added to implement `IERC20Metadata` for EVM compatibility, per `prdoc/stable2603/pr_10971.prdoc`) reads this same unconstrained byte buffer and assumes it is UTF-8:
```rust
let name = alloc::string::String::from_utf8(metadata.name.to_vec())
    .map_err(|_| Error::Revert(Revert { reason: "Invalid UTF-8 in name".into() }))?;
```
and identically for `symbol()` [1](#0-0) . Any asset owner can legitimately set `symbol`/`name` bytes to something that is not valid UTF-8 (e.g. raw binary data, matching MKR's non-string `bytes32` scenario in spirit — an ERC20-compatible surface whose metadata isn't a plain string), and the EVM-facing `name()`/`symbol()` precompile calls will then unconditionally revert for that asset, for every caller, forever (there is no way to fix already-set non-UTF8 metadata without another `set_metadata` call, and the "owner" — an untrusted, non-privileged party — controls this, not the caller/integrator).

This is the same violated invariant as the source report: EVM-facing code assumes a `string`-shaped return for token metadata that the underlying asset representation does not guarantee, causing external tooling (wallets, DEX UIs, Uniswap-V3-style integrations, or any contract using `IERC20Metadata`) to be permanently unable to read `name()`/`symbol()` for that asset via the precompile.

### Impact Explanation
Any EVM contract or off-chain tool that calls `name()`/`symbol()` on an asset's precompile address to integrate it (display, list, price, etc.) will get an unconditional revert if the asset owner (a normal, non-privileged user who created/owns the asset) set non-UTF8 metadata — intentionally or not. This breaks ERC20 compatibility/tooling integration for that asset's EVM surface, mirroring the original bug's impact (certain tokens cannot be used/integrated due to a metadata-encoding assumption). This does not cause fund loss or consensus failure, so it is best characterized as Low/Informational — a functional/compatibility defect, not a security breach with measurable loss.

### Likelihood Explanation
Low-to-medium likelihood of accidental occurrence (most asset owners will set human-readable ASCII/UTF-8 symbols), but it is trivially triggerable at will by any asset owner (deliberately or by importing metadata from an external system that isn't strict UTF-8), and there is no on-chain validation preventing it.

### Recommendation
Enforce UTF-8 validity for `name`/`symbol` at the `pallet-assets` extrinsic boundary (`do_set_metadata`/`force_set_metadata`) so invalid metadata can never be stored, or have the precompile fall back to a non-reverting placeholder (e.g., return raw bytes wrapped, or a fixed sentinel) instead of reverting when decoding fails, similar to the try-catch mitigation suggested in the original report.

### Proof of Concept
No live execution was performed (sandbox constraints per audit method); this is a static-analysis/code-tracing analog with concrete file:line evidence of the missing check chain:
1. `pallet_assets::Pallet::set_metadata` (signed, asset-owner-only) → `do_set_metadata` accepts arbitrary `Vec<u8>` for `name`/`symbol`, bounded only by length [6](#0-5) .
2. `pallet-assets-precompiles::name`/`symbol` view functions (`IERC20Metadata`-style, called via `pallet-revive` EVM precompile dispatch) then call `String::from_utf8(...)` on those same bytes and return `Error::Revert` on failure [7](#0-6) .
3. A minimal repro would: (a) call `Assets::create` + `Assets::set_metadata(origin, id, vec![0xFF, 0xFE], vec![0xFF, 0xFE], 0)` (invalid UTF-8 bytes) as the asset owner; (b) invoke the precompile's `symbol()`/`name()` selector for that asset id and observe `Error::Revert{reason: "Invalid UTF-8 in symbol"}` every time. This was not executed against a live runtime/test harness in this pass; a background Devin session with repo access would be needed to run the existing `substrate/frame/assets/precompiles/src/tests.rs` harness and add this case to confirm the revert deterministically.

### Citations

**File:** substrate/frame/assets/precompiles/src/lib.rs (L663-693)
```rust
	/// Execute the name call.
	fn name(
		asset_id: <Runtime as Config<Instance>>::AssetId,
		env: &mut impl Ext<T = Runtime>,
	) -> Result<Vec<u8>, Error> {
		env.charge(<Runtime as Config<Instance>>::WeightInfo::get_metadata())?;

		let metadata = pallet_assets::Pallet::<Runtime, Instance>::get_metadata(asset_id)
			.ok_or(Error::Revert(Revert { reason: "Metadata not found".into() }))?;

		let name = alloc::string::String::from_utf8(metadata.name.to_vec())
			.map_err(|_| Error::Revert(Revert { reason: "Invalid UTF-8 in name".into() }))?;

		Ok(IERC20::nameCall::abi_encode_returns(&name))
	}

	/// Execute the symbol call.
	fn symbol(
		asset_id: <Runtime as Config<Instance>>::AssetId,
		env: &mut impl Ext<T = Runtime>,
	) -> Result<Vec<u8>, Error> {
		env.charge(<Runtime as Config<Instance>>::WeightInfo::get_metadata())?;

		let metadata = pallet_assets::Pallet::<Runtime, Instance>::get_metadata(asset_id)
			.ok_or(Error::Revert(Revert { reason: "Metadata not found".into() }))?;

		let symbol = alloc::string::String::from_utf8(metadata.symbol.to_vec())
			.map_err(|_| Error::Revert(Revert { reason: "Invalid UTF-8 in symbol".into() }))?;

		Ok(IERC20::symbolCall::abi_encode_returns(&symbol))
	}
```

**File:** substrate/frame/assets/src/functions.rs (L1058-1070)
```rust
	/// Do set metadata
	pub(super) fn do_set_metadata(
		id: T::AssetId,
		from: &T::AccountId,
		name: Vec<u8>,
		symbol: Vec<u8>,
		decimals: u8,
	) -> DispatchResult {
		let bounded_name: BoundedVec<u8, T::StringLimit> =
			name.clone().try_into().map_err(|_| Error::<T, I>::BadMetadata)?;
		let bounded_symbol: BoundedVec<u8, T::StringLimit> =
			symbol.clone().try_into().map_err(|_| Error::<T, I>::BadMetadata)?;

```

**File:** substrate/frame/assets/src/lib.rs (L1412-1424)
```rust
		#[pallet::call_index(17)]
		#[pallet::weight(T::WeightInfo::set_metadata(name.len() as u32, symbol.len() as u32))]
		pub fn set_metadata(
			origin: OriginFor<T>,
			id: T::AssetIdParameter,
			name: Vec<u8>,
			symbol: Vec<u8>,
			decimals: u8,
		) -> DispatchResult {
			let origin = ensure_signed(origin)?;
			let id: T::AssetId = id.into();
			Self::do_set_metadata(id, &origin, name, symbol, decimals)
		}
```

**File:** substrate/frame/assets/src/lib.rs (L1468-1486)
```rust
		#[pallet::call_index(19)]
		#[pallet::weight(T::WeightInfo::force_set_metadata(name.len() as u32, symbol.len() as u32))]
		pub fn force_set_metadata(
			origin: OriginFor<T>,
			id: T::AssetIdParameter,
			name: Vec<u8>,
			symbol: Vec<u8>,
			decimals: u8,
			is_frozen: bool,
		) -> DispatchResult {
			T::ForceOrigin::ensure_origin(origin)?;
			let id: T::AssetId = id.into();

			let bounded_name: BoundedVec<u8, T::StringLimit> =
				name.clone().try_into().map_err(|_| Error::<T, I>::BadMetadata)?;

			let bounded_symbol: BoundedVec<u8, T::StringLimit> =
				symbol.clone().try_into().map_err(|_| Error::<T, I>::BadMetadata)?;

```

**File:** substrate/frame/assets/src/types.rs (L190-204)
```rust
#[derive(Clone, Encode, Decode, Eq, PartialEq, Default, Debug, MaxEncodedLen, TypeInfo)]
pub struct AssetMetadata<DepositBalance, BoundedString> {
	/// The balance deposited for this metadata.
	///
	/// This pays for the data stored in this struct.
	pub deposit: DepositBalance,
	/// The user friendly name of this asset. Limited in length by `StringLimit`.
	pub name: BoundedString,
	/// The ticker symbol for this asset. Limited in length by `StringLimit`.
	pub symbol: BoundedString,
	/// The number of decimals this asset uses to represent one unit.
	pub decimals: u8,
	/// Whether the asset metadata may be changed by a non Force origin.
	pub is_frozen: bool,
}
```
