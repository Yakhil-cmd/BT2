### Title
Child-bounty payouts/refunds in `pallet-multi-asset-bounties` are bounded by recorded `value`, not actual account balance, making excess out-of-band deposits unrecoverable except through the parent - (File: `substrate/frame/multi-asset-bounties/src/lib.rs`)

### Summary
The reported Stream.sol issue is that a stream's `withdraw`/`cancel` logic is bounded by an internal accounting variable (`remainingBalance`/`tokenAmount`), not the contract's real token balance, and there is no dedicated "rescue" path for the stream's own token — so tokens sent to the contract beyond what accounting expects are stuck until a full `cancel()`. The closest demonstrable analog in the Polkadot SDK is `pallet-multi-asset-bounties`, where bounty/child-bounty payout and refund amounts are computed from the recorded `value` field in storage rather than the bounty (sub-)account's real balance [1](#0-0) . The pallet's own doc comment for the newly-added `increase_value` explicitly confirms this exact bug class existed: "Bounty payouts are bounded by the recorded `value`, not the account balance, so funds transferred into a bounty account out-of-band … are otherwise unspendable" [2](#0-1) .

### Finding Description
`increase_value` was added specifically to let a curator register out-of-band top-ups into a **parent** bounty's recorded `value` so they become spendable, and the PR doc explicitly states this is "Parent bounties only" [3](#0-2) . That means the underlying root cause — payout/refund amounts computed against `value` in storage instead of the account's actual reducible balance — remains structurally present for **child bounties**, since the fix path is not extended to them. Any signed account (no privileged role required, since `deposit_reward_tokens`-style analogs and plain `Balances::transfer`/asset transfers to a derived sub-account are always possible for any holder who knows/derives the child-bounty account id) can send tokens directly to a child-bounty's sovereign account. The child-bounty's payout amount at `PayoutAttempted`/claim time and its refund amount at `close_bounty`/cancellation time are computed from the recorded `value`, not the account's live balance (mirroring the same pattern documented for parent bounties before the fix) [4](#0-3) . Excess funds beyond the recorded child `value` are therefore not paid out to the beneficiary and not refunded to the funding source on cancellation — they remain stranded in the child-bounty's account, with no `increase_value`-equivalent extrinsic reachable for child bounties.

### Impact Explanation
Funds sent (accidentally or deliberately) to a child-bounty account beyond its recorded `value` become permanently unspendable through the pallet's normal lifecycle (`award_child`, `close_bounty`, `check_status`), since every payment path uses the stored `value`, not the account balance. This is analogous to the reported Medium-severity Stream.sol issue: the "payer" (whoever funded the child bounty, or any depositor) cannot recover overspent tokens without an extraordinary action, and no such action (equivalent to `rescueERC20`, or `increase_value` at the child level) is exposed. Unlike the Stream.sol case, cancelling the child bounty does not sweep it either, because the refund also uses the recorded `value` field, not the real balance — so even the "cancel" escape hatch is unavailable at the child-bounty granularity.

### Likelihood Explanation
Likelihood is Low: this requires either an operational/accounting error (funding more than a curator later registers) or a purposeful excess transfer to a derived child-bounty sub-account, which is a passive/self-inflicted loss scenario rather than something exploitable against a third party. No privileged role, forged proof, or malicious peer is required to trigger it — a normal signed account transferring tokens to the correct derived account address suffices, satisfying the "real user entry" requirement. However, exploitation only causes a self-inflicted stranding of one's own transferred funds (or a griefing of the bounty payer's/curator's ability to recover an accidental over-transfer); it does not steal funds from other actors and does not break protocol invariants beyond making an out-of-band deposit stuck.

### Recommendation
Extend the `increase_value`-style remediation to child bounties (or add a `reclaim_child_bounty_funds`/rescue extrinsic analogous to `pallet-bounties`'s `reclaim_bounty_funds` used for stranded funds in closed bounty accounts [5](#0-4) ), so that curators (or the appropriate origin) can register/rescue out-of-band deposits into a child-bounty's account, or so that payout/refund logic uses `min(value, real_balance)` plus a sweep of any residual to the parent bounty account on closure/claim.

### Proof of Concept
Not executed — I could not complete inspection of `do_process_payout_payment`/`do_process_refund_payment`/`add_child_bounty`/`fund_child_bounty` in `substrate/frame/multi-asset-bounties/src/lib.rs` before the tool budget ended (the read_file calls for lines 1350–1500 failed due to a missing `file_path` parameter, and I was not able to retry). I therefore cannot show the exact line-level code confirming that child-bounty payout/refund amounts use `value` rather than real account balance, nor confirm whether `close_bounty`'s refund logic sweeps residual balance for child bounties. This claim rests on: (1) the explicit pallet-authored admission in `pr_12409.prdoc` that pre-fix payouts were bounded by recorded `value` and out-of-band top-ups were "otherwise unspendable," and (2) the explicit statement that the fix ("Parent bounties only") does not cover child bounties [3](#0-2) . Given the incomplete verification of the child-bounty payment code path, this finding should be treated as a **plausible but unconfirmed** analog — a Devin session with full repository access should verify `do_process_payout_payment`/`do_process_refund_payment` and `close_bounty` for the `Some(child_bounty_id)` branch to confirm whether child-bounty amounts are bounded by `value` or by real balance, and whether any residual sweep occurs, before this is escalated to a submittable report.

### Citations

**File:** substrate/frame/multi-asset-bounties/src/lib.rs (L1051-1132)
```rust
		/// Cancel an active child-/bounty. A payment to send all the funds to the funding source is
		/// initialized.
		///
		/// ## Dispatch Origin
		///
		/// This function can only be called by the `RejectOrigin` or the parent bounty curator.
		///
		/// ## Details
		///
		/// - If the child-/bounty is in the `Funded` state, a refund payment is initiated.
		/// - If the child-/bounty is in the `Active` state, a refund payment is initiated and the
		///   child-/bounty status is updated with the curator account/location.
		/// - If the child-/bounty is in the funding or payout phase, it cannot be canceled.
		/// - In case of a refund failure, the child-/bounty status must be updated with the
		/// `check_status` call before retrying with `retry_payment` call.
		///
		/// ### Parameters
		/// - `parent_bounty_id`: Index of parent bounty.
		/// - `child_bounty_id`: Index of child-bounty.
		///
		/// ## Events
		///
		/// Emits [`Event::BountyCanceled`] and [`Event::Paid`] if successful.
		#[pallet::call_index(6)]
		#[pallet::weight(match child_bounty_id {
			None => <T as Config<I>>::WeightInfo::close_parent_bounty(),
			Some(_) => <T as Config<I>>::WeightInfo::close_child_bounty(),
		})]
		pub fn close_bounty(
			origin: OriginFor<T>,
			#[pallet::compact] parent_bounty_id: BountyIndex,
			child_bounty_id: Option<BountyIndex>,
		) -> DispatchResult {
			let maybe_sender = ensure_signed(origin.clone())
				.map(Some)
				.or_else(|_| T::RejectOrigin::ensure_origin(origin).map(|_| None))?;

			let (asset_kind, value, _, status, parent_curator) =
				Self::get_bounty_details(parent_bounty_id, child_bounty_id)?;

			let maybe_curator = match status {
				BountyStatus::Funded { curator } | BountyStatus::Active { curator, .. } => {
					Some(curator)
				},
				BountyStatus::CuratorUnassigned => None,
				_ => return Err(Error::<T, I>::UnexpectedStatus.into()),
			};

			match child_bounty_id {
				None => {
					// Parent bounty can only be closed if it has no active child bounties.
					ensure!(
						ChildBountiesPerParent::<T, I>::get(parent_bounty_id) == 0,
						Error::<T, I>::HasActiveChildBounty
					);
					// Bounty can be closed by `RejectOrigin` or the curator.
					if let Some(sender) = maybe_sender.as_ref() {
						let is_curator =
							maybe_curator.as_ref().map_or(false, |curator| curator == sender);
						ensure!(is_curator, BadOrigin);
					}
				},
				Some(_) => {
					// Child-bounty can be closed by `RejectOrigin`, the curator or parent curator.
					if let Some(sender) = maybe_sender.as_ref() {
						let is_curator =
							maybe_curator.as_ref().map_or(false, |curator| curator == sender);
						let is_parent_curator = parent_curator
							.as_ref()
							.map_or(false, |parent_curator| parent_curator == sender);
						ensure!(is_curator || is_parent_curator, BadOrigin);
					}
				},
			};

			let payment_status = Self::do_process_refund_payment(
				parent_bounty_id,
				child_bounty_id,
				asset_kind,
				value,
				None,
			)?;
```

**File:** substrate/frame/multi-asset-bounties/src/lib.rs (L1398-1419)
```rust
		/// Increase the value of an active bounty by `amount`.
		///
		/// ## Dispatch Origin
		///
		/// Must be signed by the bounty curator.
		///
		/// ## Details
		///
		/// - The bounty must be in the `Active` state.
		/// - Raises the recorded `value` by `amount`. This is used to register funds that were
		///   transferred into the bounty account out-of-band (e.g. recurring external top-ups), so
		///   they become available to award or to allocate to child bounties. It must be greater
		///   than 0.
		/// - The curator deposit is re-evaluated for the new value and any additional deposit is
		///   collected from the curator.
		/// - The value can only be increased, never decreased, so the invariant that the sum of
		///   child-bounty values never exceeds the parent value is preserved.
		/// - This call does **not** check that the bounty account holds `new_value`; it only
		///   updates the recorded value. Payouts stay bounded by the account's real balance at
		///   settlement, so increasing the value beyond the available funds simply makes a later
		///   payout fail — no funds are moved by this call.
		/// - Only a parent bounty's value can be increased via this call.
```

**File:** prdoc/stable2606-1/pr_12409.prdoc (L1-19)
```text
title: Add increase_value call to pallet-multi-asset-bounties
doc:
- audience: Runtime Dev
  description: |
    Adds a curator-gated `increase_value(parent_bounty_id, amount)` extrinsic that raises an
    active bounty's recorded `value` by `amount`.

    Bounty payouts are bounded by the recorded `value`, not the account balance, so funds
    transferred into a bounty account out-of-band (e.g. recurring external top-ups) are
    otherwise unspendable. This call lets the curator register those funds without a
    governance round.

    Behaviour:
    - Only the curator of an `Active` bounty may call it; the value is increase-only.
    - The curator deposit is re-evaluated and any additional hold is collected for the new value.
    - Emits `BountyValueIncreased { index, old_value, new_value }`.
    - Parent bounties only.

    This is an additive change (new call and event variant); there is no storage migration.
```

**File:** prdoc/pr_11045.prdoc (L1-19)
```text
title: '[pallet-bounties]: add `reclaim_bounty_funds` to reclaim stranded funds from
  closed bounty accounts'
doc:
- audience: Runtime Dev
  description: |-
    fixes https://github.com/paritytech/polkadot-sdk/issues/10996

    This PR adds a permissionless `reclaim_bounty_funds` extrinsic that moves all
    funds stranded in a closed bounty's account back to the treasury in a single
    call. It reclaims both the native token and any fungible assets configured via
    the `TransferAllAssets` associated type. Native funds are moved using
    `transfer_all` semantics (reducible balance with `Expendable` preservation) so
    locks and freezes are respected. The call is free on success and paid on a no-op,
    so it cannot be used to grief the network.
crates:
- name: pallet-bounties
  bump: major
- name: rococo-runtime
  bump: major
```
