No vulnerability found for this question.

**Rationale:** The Sherlock report describes an *undisclosed* weak-randomness bug in bespoke Solidity code (`ERC20Incentive.drawRaffle`) that silently seeds a PRNG with `block.prevrandao + block.timestamp`. Searching polkadot-sdk for an analogous "attacker manipulates weak randomness to steal funds" pattern surfaces two things, neither of which qualifies as a new finding:

1. `pallet_insecure_randomness_collective_flip` is explicitly named and documented as insecure — its own module docs state the low-influence hash-based randomness is "entirely manipulatable by the author of the parent block" and the umbrella crate re-export doc literally reads "Insecure do not use in production." [1](#0-0) [2](#0-1)  This is a disclosed, intentional trade-off pallet meant only for testing/demo use, not a hidden vulnerability.

2. `pallet_lottery`, which does implement an actual raffle/lottery mechanic reachable via a signed `buy_ticket` extrinsic, is generic over `T::Randomness: Randomness<...>` and in the reference node runtime it's wired to that same insecure collective-flip pallet, but this is again a documented example-runtime configuration choice, not a defect in `pallet_lottery` itself. [3](#0-2) [4](#0-3)  Any production-grade runtime is expected to configure `Randomness` with a real VRF-based source instead, and polkadot-sdk already provides one: `pallet_babe`'s `RandomnessFromOneEpochAgo`/`RandomnessFromTwoEpochsAgo`/`ParentBlockRandomness`, built on Schnorrkel VRF outputs collected across an epoch specifically to avoid single-block-producer bias. [5](#0-4) [6](#0-5) 

Per the scan rules, config-only / dependency-only findings and already-known, explicitly-labeled trade-offs are excluded, and file-list membership in an example runtime is not itself a vulnerability. There is no undisclosed bypass here: the weak-randomness risk is already named, documented, and a secure alternative (BABE VRF randomness) is provided in the same codebase. No demonstrable, novel FRAME/XCM-level analog to the Sherlock finding exists in this repo.

### Citations

**File:** substrate/frame/insecure-randomness-collective-flip/src/lib.rs (L127-137)
```rust
impl<T: Config> Randomness<T::Hash, BlockNumberFor<T>> for Pallet<T> {
	/// This randomness uses a low-influence function, drawing upon the block hashes from the
	/// previous 81 blocks. Its result for any given subject will be known far in advance by anyone
	/// observing the chain. Any block producer has significant influence over their block hashes
	/// bounded only by their computational resources. Our low-influence function reduces the actual
	/// block producer's influence over the randomness, but increases the influence of small
	/// colluding groups of recent block producers.
	///
	/// WARNING: Hashing the result of this function will remove any low-influence properties it has
	/// and mean that all bits of the resulting value are entirely manipulatable by the author of
	/// the parent block, who can determine the value of `parent_hash`.
```

**File:** umbrella/src/lib.rs (L531-533)
```rust
/// Insecure do not use in production: FRAME randomness collective flip pallet.
#[cfg(feature = "pallet-insecure-randomness-collective-flip")]
pub use pallet_insecure_randomness_collective_flip;
```

**File:** substrate/frame/lottery/src/lib.rs (L144-145)
```rust
		/// Something that provides randomness in the runtime.
		type Randomness: Randomness<Self::Hash, BlockNumberFor<Self>>;
```

**File:** substrate/bin/node/runtime/src/lib.rs (L1890-1901)
```rust
impl pallet_lottery::Config for Runtime {
	type PalletId = LotteryPalletId;
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type Randomness = RandomnessCollectiveFlip;
	type RuntimeEvent = RuntimeEvent;
	type ManagerOrigin = EnsureRoot<AccountId>;
	type MaxCalls = MaxCalls;
	type ValidateCall = Lottery;
	type MaxGenerateRandom = MaxGenerateRandom;
	type WeightInfo = pallet_lottery::weights::SubstrateWeight<Runtime>;
}
```

**File:** substrate/frame/babe/src/randomness.rs (L18-53)
```rust
//! Provides multiple implementations of the randomness trait based on the on-chain epoch
//! randomness collected from VRF outputs.

use super::{
	AuthorVrfRandomness, Config, EpochStart, NextRandomness, Randomness, RANDOMNESS_LENGTH,
};
use frame_support::traits::Randomness as RandomnessT;
use frame_system::pallet_prelude::BlockNumberFor;
use sp_runtime::traits::{Hash, One, Saturating};

/// Randomness usable by consensus protocols that **depend** upon finality and take action
/// based upon on-chain commitments made during the epoch before the previous epoch.
///
/// An off-chain consensus protocol requires randomness be finalized before usage, but one
/// extra epoch delay beyond `RandomnessFromOneEpochAgo` suffices, under the assumption
/// that finality never stalls for longer than one epoch.
///
/// All randomness is relative to commitments to any other inputs to the computation: If
/// Alice samples randomness near perfectly using radioactive decay, but then afterwards
/// Eve selects an arbitrary value with which to xor Alice's randomness, then Eve always
/// wins whatever game they play.
///
/// All input commitments used with `RandomnessFromTwoEpochsAgo` should come from at least
/// three epochs ago. We require BABE session keys be registered at least three epochs
/// before being used to derive `ParentBlockRandomness` for example.
///
/// All users learn `RandomnessFromTwoEpochsAgo` when epoch `current_epoch - 1` starts,
/// although some learn it a few block earlier inside epoch `current_epoch - 2`.
///
/// Adversaries with enough block producers could bias this randomness by choosing upon
/// what their block producers build at the end of epoch `current_epoch - 2` or the
/// beginning epoch `current_epoch - 1`, or skipping slots at the end of epoch
/// `current_epoch - 2`.
///
/// Adversaries should not possess many block production slots towards the beginning or
/// end of every epoch, but they possess some influence over when they possess more slots.
```

**File:** substrate/frame/support/src/traits/randomness.rs (L20-38)
```rust
/// A trait that is able to provide randomness.
///
/// Being a deterministic blockchain, real randomness is difficult to come by, different
/// implementations of this trait will provide different security guarantees. At best,
/// this will be randomness which was hard to predict a long time ago, but that has become
/// easy to predict recently.
pub trait Randomness<Output, BlockNumber> {
	/// Get the most recently determined random seed, along with the time in the past
	/// since when it was determinable by chain observers.
	///
	/// `subject` is a context identifier and allows you to get a different result to
	/// other callers of this function; use it like `random(&b"my context"[..])`.
	///
	/// NOTE: The returned seed should only be used to distinguish commitments made before
	/// the returned block number. If the block number is too early (i.e. commitments were
	/// made afterwards), then ensure no further commitments may be made and repeatedly
	/// call this on later blocks until the block number returned is later than the latest
	/// commitment.
	fn random(subject: &[u8]) -> (Output, BlockNumber);
```
