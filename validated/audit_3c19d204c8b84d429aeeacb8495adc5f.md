## Analysis Result

I found a structurally identical analog to the reported vault bug in the crowdloan pallet's `do_contribute` function, which enforces the exact same "minimum-amount AND max-cap" check pattern that can interact to permanently strand fund-raising capacity. [1](#0-0) 

### Title
Crowdloan `contribute()` Can Permanently Strand a Sliver of Fund Capacity When Remaining Cap Falls Below `MinContribution` - (File: `polkadot/runtime/common/src/crowdloan/mod.rs`)

### Summary
The `do_contribute` function of `pallet-crowdloan` enforces `value >= T::MinContribution::get()` and, after tentatively adding `value` to `fund.raised`, enforces `fund.raised <= fund.cap`. These two independent bound checks, exactly analogous to the Solidity `_deposit()` bug's `minimumSupply`/`capacity` checks, can interact so that once `cap - raised < MinContribution`, no contribution of any size can succeed for the remainder of the crowdloan, permanently stranding that sliver of the fund's cap.

### Finding Description
`do_contribute` is reachable via the signed extrinsic `Crowdloan::contribute(origin, index, value, signature)`, which any signed account can call while the fund is open. [2](#0-1) 

Inside `do_contribute`, the two relevant guards are:

```rust
ensure!(value >= T::MinContribution::get(), Error::<T>::ContributionTooSmall);
let mut fund = Funds::<T>::get(index).ok_or(Error::<T>::InvalidParaId)?;
fund.raised = fund.raised.checked_add(&value).ok_or(Error::<T>::Overflow)?;
ensure!(fund.raised <= fund.cap, Error::<T>::CapExceeded);
``` [3](#0-2) 

`fund.cap` is a hard, fixed ceiling set at `create()`/`edit()` time [4](#0-3) , while `T::MinContribution` is a fixed runtime constant, e.g. `MinContribution: Balance = 3_000 * CENTS` on Rococo [5](#0-4)  or `100 * CENTS` on the staking-async relay-chain runtime [6](#0-5) .

Once `fund.cap - fund.raised < T::MinContribution::get()`, every subsequent `contribute()` call fails:
- Any `value < MinContribution` is rejected by `ContributionTooSmall`.
- Any `value >= MinContribution` is rejected by `CapExceeded` because `raised + value > cap`.

This is precisely the same class of bug as the reported Solidity `_deposit()` flaw: two independently-valid bound checks that jointly create an unreachable "dead zone" near the cap. Any signed, unprivileged contributor can trigger this state simply by making an ordinary contribution that leaves a remainder smaller than `MinContribution` (this requires no special privilege — it is literally what the test suite exercises: `Crowdloan::contribute(RuntimeOrigin::signed(1), para, 101, None)` against a cap of `1000` leaves `899` remaining, and a follow-up of `900` is rejected with `CapExceeded` [7](#0-6) ; a contributor could instead deliberately leave a remainder `< MinContribution` to grief the campaign).

### Impact Explanation
The practical impact is materially weaker than in the vault case. In the vault report, the stranded capacity represents *depositors' capital sitting idle*, directly reducing yield for existing depositors — a continuous economic cost. In the crowdloan analog, the stranded amount is *unraised* capacity: no one's existing funds are frozen or devalued; the parachain manager simply cannot raise the very last `< MinContribution` worth of its cap for the remainder of the campaign (until `edit()` is called by Root to change `cap`/reduce the gap, or the crowdloan ends). Given `MinContribution` values are dust-sized relative to typical crowdloan caps (e.g. 3,000 CENTS vs. caps typically denominated in GRAND/DOT), the maximum possible "loss" of raisable capacity is bounded and small, and does not constitute theft, unbacked issuance, unauthorized dispatch, or irreversible freezing of user funds. This does not meet the bar for Critical/High impact.

### Likelihood Explanation
Any signed account holder can trivially trigger the dead-zone (no privileged role, governance, or malicious infrastructure required) — it can occur naturally near the end of a popular crowdloan, or be deliberately induced by a griefer contributing an amount that leaves `cap - raised < MinContribution`. Reachability through the real extrinsic dispatch path (`Crowdloan::contribute` → `do_contribute`) is confirmed by the pallet's own test, `contribute_handles_basic_errors`, which demonstrates `CapExceeded` firing once the cap's headroom is exhausted [8](#0-7) .

### Recommendation
Mirror the fix recommended for the original report: clamp the effective minimum contribution to `min(T::MinContribution::get(), fund.cap - fund.raised)` when `fund.cap - fund.raised < T::MinContribution::get()`, so the last sliver of a crowdloan's cap can still be filled by a smaller-than-`MinContribution` contribution instead of becoming permanently unreachable.

### Proof of Concept
Using the pallet's own mock runtime (`MinContribution = 10`, per `new_test_ext()` [9](#0-8) ):
1. `Crowdloan::create(signed(1), para, cap=1000, ..)`.
2. `Crowdloan::contribute(signed(1), para, 991, None)` → `Ok`, `fund.raised = 991`, remaining headroom = 9 (< `MinContribution=10`).
3. `Crowdloan::contribute(signed(2), para, 9, None)` → fails with `Error::ContributionTooSmall` (9 < 10).
4. `Crowdloan::contribute(signed(2), para, 10, None)` → fails with `Error::CapExceeded` (991+10=1001 > 1000).
5. No value of `value` can ever be accepted again for this fund while `raised = 991`; the remaining 9 units of cap are permanently unreachable for the life of the crowdloan (existing repo test `contribute_handles_basic_errors` already exercises the `CapExceeded` half of this pattern at [7](#0-6) ; step 3 above (`ContributionTooSmall` on the remaining headroom) is the missing half completing the dead-zone, confirmed by the guard order at [3](#0-2) ).

Guards that fail: `Error::<T>::ContributionTooSmall` and `Error::<T>::CapExceeded`, both of which are hit for every possible `value` once the gap condition holds — confirming the dead-zone is real and deterministic, not merely theoretical.

### Citations

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L152-155)
```rust
	/// then everyone may withdraw their funds.
	pub end: BlockNumber,
	/// A hard-cap on the amount that may be contributed.
	pub cap: Balance,
```

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L446-453)
```rust
		pub fn contribute(
			origin: OriginFor<T>,
			#[pallet::compact] index: ParaId,
			#[pallet::compact] value: BalanceOf<T>,
			signature: Option<MultiSignature>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Self::do_contribute(who, index, value, signature, KeepAlive)
```

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L749-759)
```rust
	fn do_contribute(
		who: T::AccountId,
		index: ParaId,
		value: BalanceOf<T>,
		signature: Option<MultiSignature>,
		existence: ExistenceRequirement,
	) -> DispatchResult {
		ensure!(value >= T::MinContribution::get(), Error::<T>::ContributionTooSmall);
		let mut fund = Funds::<T>::get(index).ok_or(Error::<T>::InvalidParaId)?;
		fund.raised = fund.raised.checked_add(&value).ok_or(Error::<T>::Overflow)?;
		ensure!(fund.raised <= fund.cap, Error::<T>::CapExceeded);
```

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L1058-1076)
```rust
	parameter_types! {
		pub const SubmissionDeposit: u64 = 1;
		pub const MinContribution: u64 = 10;
		pub const CrowdloanPalletId: PalletId = PalletId(*b"py/cfund");
		pub const RemoveKeysLimit: u32 = 10;
		pub const MaxMemoLength: u8 = 32;
	}

	impl Config for Test {
		type RuntimeEvent = RuntimeEvent;
		type SubmissionDeposit = SubmissionDeposit;
		type MinContribution = MinContribution;
		type PalletId = CrowdloanPalletId;
		type RemoveKeysLimit = RemoveKeysLimit;
		type Registrar = TestRegistrar<Test>;
		type Auctioneer = TestAuctioneer;
		type MaxMemoLength = MaxMemoLength;
		type WeightInfo = crate::crowdloan::TestWeightInfo;
	}
```

**File:** polkadot/runtime/common/src/crowdloan/mod.rs (L1406-1413)
```rust
			assert_ok!(Crowdloan::create(RuntimeOrigin::signed(1), para, 1000, 1, 4, 9, None));
			assert_ok!(Crowdloan::contribute(RuntimeOrigin::signed(1), para, 101, None));

			// Cannot contribute past the limit
			assert_noop!(
				Crowdloan::contribute(RuntimeOrigin::signed(2), para, 900, None),
				Error::<Test>::CapExceeded
			);
```

**File:** polkadot/runtime/rococo/src/lib.rs (L1255-1262)
```rust
parameter_types! {
	pub const CrowdloanId: PalletId = PalletId(*b"py/cfund");
	pub const SubmissionDeposit: Balance = 3 * GRAND;
	pub const MinContribution: Balance = 3_000 * CENTS;
	pub const RemoveKeysLimit: u32 = 1000;
	// Allow 32 bytes for an additional memo to a crowdloan.
	pub const MaxMemoLength: u8 = 32;
}
```

**File:** substrate/frame/staking-async/runtimes/rc/src/lib.rs (L1679-1686)
```rust
parameter_types! {
	pub const CrowdloanId: PalletId = PalletId(*b"py/cfund");
	pub const SubmissionDeposit: Balance = 100 * 100 * CENTS;
	pub const MinContribution: Balance = 100 * CENTS;
	pub const RemoveKeysLimit: u32 = 500;
	// Allow 32 bytes for an additional memo to a crowdloan.
	pub const MaxMemoLength: u8 = 32;
}
```
