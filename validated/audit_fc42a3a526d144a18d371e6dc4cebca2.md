### Title
`pallet-assets::refund_other` permanently blocks a depositor's deposit refund when the target account is frozen - (File: `substrate/frame/assets/src/functions.rs`)

### Summary
The Sherlock report describes a funder who cannot reclaim their deposit because the recipient (themselves) is blocked from receiving the token (e.g. a USDC blacklist), and the refund path has no fallback destination. The same root cause — an unrelated "frozen/blocked" flag on an account gating an otherwise-independent deposit refund, with no alternate destination — exists in `pallet-assets`'s `do_refund_other`, which is reachable through the public `refund_other` extrinsic.

### Finding Description
`pallet-assets` lets a depositor pay the existential-deposit-equivalent reserve for another account's asset entry (`touch_other`/`Account::reason = DepositFrom`), and later reclaim it via the permissionless `refund_other` extrinsic, which dispatches to `do_refund_other`: [1](#0-0) 

Note the guard `ensure!(!account.status.is_frozen(), Error::<T, I>::Frozen);` at line 428. This checks whether the *target account `who`'s* asset entry is frozen — a status controlled solely by the asset's `Freezer`/admin, not by the `depositor` who is trying to reclaim their own native-currency reserve. Even though:
- the deposit being refunded is a completely separate native-currency reserve (`T::Currency::unreserve(&depositor, deposit)`), unrelated to the frozen asset balance itself, and
- `account.balance.is_zero()` is already required (so freezing serves no purpose in preventing balance movement here),

the refund still reverts with `Error::Frozen` as long as the account remains frozen. Compare this with the self-refund path `do_refund`, which only checks the asset's *global* status (`Live | Frozen`), not the individual account's frozen flag: [2](#0-1) 

This asymmetry means the `depositor` (a bystander who merely paid to enable someone else's asset account) is left with a permanently-reserved deposit until a third party (the asset's Freezer/admin) decides to lift the freeze — the depositor has no way to redirect the refund or force it through, exactly mirroring the original report's missing "specify a `to` address" recommendation.

### Impact Explanation
The `depositor`'s native currency reserve is locked indefinitely (subject entirely to the asset admin's/Freezer's discretion) even though nothing about their own funds or actions is at issue. This is a fund-availability/DoS issue on a legitimate, unprivileged actor (the depositor), matching the Medium classification of the original report: the funds are not lost forever by protocol design, but the affected party has no self-service recovery path and depends on a third party's cooperation.

### Likelihood Explanation
Likelihood is limited by the precondition that the asset's Freezer/admin freezes the specific account (`account.status.is_frozen()`), which is a normal, expected asset-management action (e.g. compliance freeze), not an attacker exploit. This mirrors the original report's own precondition (an external stablecoin issuer blacklisting the funder) — in both cases the triggering action lies outside the depositor's/funder's control, and the vulnerability is purely the missing fallback/self-service path in the refund logic.

### Recommendation
Either:
- allow `do_refund_other` to proceed independently of `account.status.is_frozen()` when only the (already-verified-zero) balance and a separate native-currency deposit are involved, since freezing the asset balance provides no protection benefit here, or
- provide an explicit `force_refund_other`/root-level path (or an alternate-recipient parameter) so the deposit can be recovered without depending on the freeze being lifted.

### Proof of Concept
No executable PoC was run (no tool access to a Rust/FRAME test harness in this session). The guard is directly visible in code: `substrate/frame/assets/src/functions.rs:428` (`ensure!(!account.status.is_frozen(), Error::<T, I>::Frozen);`) inside `do_refund_other`, invoked from the public, permissionless `refund_other` extrinsic in `substrate/frame/assets/src/lib.rs`. A minimal repro would: (1) `create`/`touch_other` an asset account for `who` funded by `depositor`; (2) have the asset's Freezer call `freeze(who)`; (3) have `depositor` call `refund_other(id, who)` and observe it fails with `Error::<T,I>::Frozen` despite `who`'s balance being zero and the deposit being an unrelated native-currency reserve. This was reasoned from static code inspection only; it has not been executed against a running node/test in this session, and I could not fully verify whether `do_refund` (self-refund path) is reachable as an alternative recovery route for `who` themselves to unfreeze the situation indirectly — that would need to be checked in a live test harness before treating this as conclusively unrecoverable.

### Citations

**File:** substrate/frame/assets/src/functions.rs (L371-384)
```rust
	pub(super) fn do_refund(id: T::AssetId, who: T::AccountId, allow_burn: bool) -> DispatchResult {
		use AssetStatus::*;
		use ExistenceReason::*;

		let mut account = Account::<T, I>::get(&id, &who).ok_or(Error::<T, I>::NoDeposit)?;
		ensure!(matches!(account.reason, Consumer | DepositHeld(..)), Error::<T, I>::NoDeposit);
		let mut details = Asset::<T, I>::get(&id).ok_or(Error::<T, I>::Unknown)?;
		ensure!(matches!(details.status, Live | Frozen), Error::<T, I>::IncorrectStatus);
		ensure!(account.balance.is_zero() || allow_burn, Error::<T, I>::WouldBurn);
		Self::ensure_account_can_die(id.clone(), &who)?;

		if let Some(deposit) = account.reason.take_deposit() {
			T::Currency::unreserve(&who, deposit);
		}
```

**File:** substrate/frame/assets/src/functions.rs (L414-435)
```rust
	/// Refunds the `DepositFrom` of an account only if its balance is zero.
	///
	/// If the `maybe_check_caller` parameter is specified, it must match the account that provided
	/// the deposit or must be the admin of the asset.
	pub(super) fn do_refund_other(
		id: T::AssetId,
		who: &T::AccountId,
		maybe_check_caller: Option<T::AccountId>,
	) -> DispatchResult {
		let mut account = Account::<T, I>::get(&id, &who).ok_or(Error::<T, I>::NoDeposit)?;
		let (depositor, deposit) =
			account.reason.take_deposit_from().ok_or(Error::<T, I>::NoDeposit)?;
		let mut details = Asset::<T, I>::get(&id).ok_or(Error::<T, I>::Unknown)?;
		ensure!(details.status == AssetStatus::Live, Error::<T, I>::AssetNotLive);
		ensure!(!account.status.is_frozen(), Error::<T, I>::Frozen);
		if let Some(caller) = maybe_check_caller {
			ensure!(caller == depositor || caller == details.admin, Error::<T, I>::NoPermission);
		}
		ensure!(account.balance.is_zero(), Error::<T, I>::WouldBurn);
		Self::ensure_account_can_die(id.clone(), who)?;

		T::Currency::unreserve(&depositor, deposit);
```
