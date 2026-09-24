Based on extensive investigation across the XCM location-matching stack, `pallet-revive` precompile addressing, and FRAME call-filter implementations, I did not find a reachable analog of the reported bug class.

The reported vulnerability is a fundamentally string-based, unanchored substring match (`urlFilter` without `|`/`||` anchors, matched against the full request URL) that lets an attacker embed the trusted trigger string anywhere in an attacker-controlled URL, causing a sensitive credential (the PRT cookie) to be attached to the wrong destination.

Every analogous "prefix/contains" check found in `polkadot-sdk` operates on **structured, typed data** rather than raw strings, and is properly anchored:

- `Location::starts_with` / `Junctions::starts_with` compare `parents` count equality plus an ordered, index-by-index junction comparison from position 0 — this is a structural prefix check, not a substring search, so an attacker cannot "embed" a trusted `Location` inside an unrelated one to fool the check. [1](#0-0) [2](#0-1) 

- `xcm-builder`'s `StartsWith`, `FromSiblingParachain`, `FromNetwork`, and `origin_aliases.rs`'s `AliasChildLocation` all delegate to this same structural `starts_with`/`match_and_split`, used for XCM reserve/teleport/alias trust decisions. [3](#0-2) [4](#0-3) 

- `pallet-revive`'s `AddressMatcher::Prefix`/`BuiltinAddressMatcher` explicitly compares fixed byte ranges (`address[4..20]` against a base address) — the "free" bytes are by design (documented) and don't allow embedding a trusted marker at an unexpected offset to defeat the check.
<invoke name="grep_search">
<parameter name="pattern">nothing</parameter>
</invoke>

### Citations

**File:** polkadot/xcm/src/v5/location.rs (L294-296)
```rust
	pub fn starts_with(&self, prefix: &Location) -> bool {
		self.parents == prefix.parents && self.interior.starts_with(&prefix.interior)
	}
```

**File:** polkadot/xcm/src/v5/junctions.rs (L610-612)
```rust
		let inverted = context.invert_target(&target).unwrap();
		assert_eq!(inverted, expected);

```

**File:** polkadot/xcm/xcm-builder/src/matches_location.rs (L25-39)
```rust
/// An implementation of `Contains` that checks for `Location` or
/// `InteriorLocation` if starts with the provided type `T`.
pub struct StartsWith<T, L = Location>(core::marker::PhantomData<(T, L)>);
impl<T: Get<L>, L: TryInto<Location> + Clone> Contains<L> for StartsWith<T, L> {
	fn contains(location: &L) -> bool {
		let latest_location: Location = if let Ok(location) = (*location).clone().try_into() {
			location
		} else {
			return false;
		};
		let latest_t =
			if let Ok(location) = T::get().try_into() { location } else { return false };
		latest_location.starts_with(&latest_t)
	}
}
```

**File:** cumulus/parachains/runtimes/assets/common/src/matching.rs (L43-67)
```rust
/// Checks if `a` is from sibling location `b`. Checks that `Location-a` starts with
/// `Location-b`, and that the `ParaId` of `b` is not equal to `a`.
pub struct FromSiblingParachain<SelfParaId, L = Location>(
	core::marker::PhantomData<(SelfParaId, L)>,
);
impl<SelfParaId: Get<ParaId>, L: TryFrom<Location> + TryInto<Location> + Clone + Debug>
	ContainsPair<L, L> for FromSiblingParachain<SelfParaId, L>
{
	fn contains(a: &L, b: &L) -> bool {
		tracing::trace!(target: "xcm:contains", ?a, ?b, "FromSiblingParachain");
		// We convert locations to latest
		let a = match ((*a).clone().try_into(), (*b).clone().try_into()) {
			(Ok(a), Ok(b)) if a.starts_with(&b) => a, // `a` needs to be from `b` at least
			_ => return false,
		};

		// here we check if sibling
		match a.unpack() {
			(1, interior) => {
				matches!(interior.first(), Some(Parachain(sibling_para_id)) if sibling_para_id.ne(&u32::from(SelfParaId::get())))
			},
			_ => false,
		}
	}
}
```
