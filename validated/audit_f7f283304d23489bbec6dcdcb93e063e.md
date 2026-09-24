[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** substrate/frame/asset-conversion/src/lib.rs (L1168-1181)
```rust
		fn swap(
			sender: &T::AccountId,
			path: &BalancePath<T>,
			send_to: &T::AccountId,
			keep_alive: bool,
		) -> Result<(), DispatchError> {
			let (asset_in, amount_in) = path.first().ok_or(Error::<T>::InvalidPath)?;
			let credit_in = Self::withdraw(asset_in.clone(), sender, *amount_in, keep_alive)?;

			let credit_out = Self::credit_swap(credit_in, path).map_err(|(_, e)| e)?;
			T::Assets::resolve(send_to, credit_out).map_err(|_| Error::<T>::BelowMinimum)?;

			Ok(())
		}
```

**File:** substrate/frame/bounties/src/benchmarking.rs (L400-419)
```rust
		let bounty_account = Bounties::<T, I>::bounty_account_id(bounty_id);
		// Drop the bounty record so its account counts as stale.
		crate::Bounties::<T, I>::remove(bounty_id);
		BountyDescriptions::<T, I>::remove(bounty_id);

		// Mint all relevant assets into the bounty account so the benchmark exercises real
		// transfers instead of being a no-op for runtimes with non-trivial TransferAllAssets.
		T::TransferAllAssets::ensure_successful(&bounty_account);

		assert!(
			!T::Currency::free_balance(&bounty_account).is_zero(),
			"Bounty account should have a balance to reclaim"
		);

		let caller: T::AccountId = whitelisted_caller();

		#[extrinsic_call]
		_(RawOrigin::Signed(caller), bounty_id);

		assert_last_event::<T, I>(Event::BountyFundsReclaimed { bounty_id }.into());
```

**File:** substrate/frame/nomination-pools/src/tests.rs (L445-463)
```rust
			// When: ED is decreased and reward account has excess ED frozen
			ExistentialDeposit::set(5);

			let bonded_pool = BondedPool::<Runtime>::get(1).unwrap();
			let owner = bonded_pool.roles.depositor;

			assert_eq!(owner, 10);

			// And:: adjust ED deposit is called
			let pre_balance = Currency::free_balance(&owner);
			assert_ok!(Pools::adjust_pool_deposit(RuntimeOrigin::signed(owner), 1));

			// Then: excess ED is claimed by the pool depositor
			assert_eq!(Currency::free_balance(&owner), pre_balance + 45);

			assert_eq!(
				pool_events_since_last_call(),
				vec![Event::MinBalanceExcessAdjusted { pool_id: 1, amount: 45 },]
			);
```

**File:** prdoc/stable2603/pr_10399.prdoc (L1-8)
```text
title: Limit the authority to adjust nomination pool deposits
doc:
- audience: Runtime Dev
  description: |-
    Up until this point, when EDs of chains using nomination pools were reduced, the subsequent reward account funds in exces could be claimed by anyone, despite the fact that they had been typically provided at the beginning by the pool owner. We therefore limit access to these funds only to the pool owner and the (optional) root account when EDs get reduced. The restriction does not apply to the increase in EDs, as these imply that funds are transferred into the pool rather than out of it.
crates:
- name: pallet-nomination-pools
  bump: major
```
