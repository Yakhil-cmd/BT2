No vulnerability found for this question.

The reported issue—a governance contract lacking a `transferETH`-style rescue function—describes a missing convenience feature, not an exploitable vulnerability: there is no attacker-controlled entry point, no unauthorized dispatch, and no path to theft or loss for any party other than governance itself choosing not to add a recovery mechanism. Reviewing the Polkadot SDK's actual handling of stranded/stuck native funds, the codebase already contains multiple explicit, permissionless recovery mechanisms designed for exactly this class of situation:

- `pallet-bounties::reclaim_bounty_funds` sweeps stranded native and asset balances from closed bounty accounts back to the treasury, respecting locks/freezes via `transfer_all` semantics [1](#0-0) .
- `pallet-treasury` has had dedicated migrations to clear stuck bonds/proposals and drain residual balances into safe destinations [2](#0-1) [3](#0-2) .
- `pallet-democracy` ships an `unlock_and_unreserve_all_funds` migration specifically to release funds locked/reserved by the pallet [4](#0-3) .
- `pallet-revive` provides a `dispatch_as_fallback_account` recovery path for funds trapped in fallback accounts [5](#0-4) .

These demonstrate that where the SDK does hold native funds in pallet-controlled accounts, recovery paths are deliberately engineered as governance/permissionless extrinsics or migrations—consistent with intended design, not a defect. Since the original finding fundamentally concerns absence of an administrative convenience function with no attacker-exploitable path, no true FRAME/XCM analog exists that satisfies the required "attacker-controlled input causing measurable loss through checks/mutation" pattern mandated by the scan methodology.

### Citations

**File:** substrate/frame/bounties/src/lib.rs (L1058-1090)
```rust
		#[pallet::call_index(11)]
		#[pallet::weight(<T as Config<I>>::WeightInfo::reclaim_bounty_funds())]
		pub fn reclaim_bounty_funds(
			origin: OriginFor<T>,
			#[pallet::compact] bounty_id: BountyIndex,
		) -> DispatchResultWithPostInfo {
			ensure_signed(origin)?;

			// A live bounty still manages its account, so leave it untouched.
			ensure!(!Bounties::<T, I>::contains_key(bounty_id), Error::<T, I>::BountyStillActive);

			debug_assert!(
				T::ChildBountyManager::child_bounties_count(bounty_id) == 0,
				"child bounties should not exist for a closed bounty"
			);

			let bounty_account = Self::bounty_account_id(bounty_id);
			let treasury_account = Self::account_id();

			let transferred = T::TransferAllAssets::force_transfer_all_assets(
				&bounty_account,
				&treasury_account,
			)?;

			// Free only if something moved, otherwise paid to prevent griefing.
			if !transferred {
				return Ok(Pays::Yes.into());
			}

			Self::deposit_event(Event::<T, I>::BountyFundsReclaimed { bounty_id });

			Ok(Pays::No.into())
		}
```

**File:** prdoc/stable2412/pr_5892.prdoc (L1-17)
```text
# Schema: Polkadot SDK PRDoc Schema (prdoc) v1.0.0
# See doc at https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/prdoc/schema_user.json

title: "Treasury: add migration to clean up unapproved deprecated proposals"

doc:
  - audience: Runtime Dev
    description: |
      It is no longer possible to create `Proposals` storage item in `pallet-treasury` due to migration from
      governance v1 model but there are some `Proposals` whose bonds are still on hold with no way to release them.
      The purpose of this migration is to clear `Proposals` which are stuck and return bonds to the proposers.

crates:
    - name: pallet-treasury
      bump: patch
    - name: rococo-runtime
      bump: patch
```

**File:** prdoc/stable2606/pr_11763.prdoc (L1-12)
```text
title: '[westend] Remove pallet_treasury from RC and clean up satellite matchers'
doc:
- audience: Runtime Dev
  description: |-
    Remove pallet_treasury entirely from Westend relay chain.
    Drain residual balances from the legacy `py/trsry`-derived account into the local
    DAP satellite buffer on the relay and on each Westend system parachain
    (bridge-hub, collectives, coretime, people).
    Remove RelayTreasuryLocation matchers from all Westend system parachains.

    Closes #11705.
crates:
```

**File:** substrate/frame/democracy/src/migrations/mod.rs (L18-19)
```rust
/// Migration to unlock and unreserve all pallet funds.
pub mod unlock_and_unreserve_all_funds;
```

**File:** substrate/frame/revive/src/tests/pvm.rs (L4049-4059)
```rust
		let call = RuntimeCall::Balances(pallet_balances::Call::transfer_all {
			dest: EVE,
			keep_alive: false,
		});

		// she now uses the recovery function to move all funds from the fallback
		// account to her real account
		<Pallet<Test>>::dispatch_as_fallback_account(RuntimeOrigin::signed(EVE), Box::new(call))
			.unwrap();
		assert_eq!(<Test as Config>::Currency::total_balance(&EVE_FALLBACK), 0);
		assert_eq!(<Test as Config>::Currency::total_balance(&EVE), initial_contract_balance + 100);
```
