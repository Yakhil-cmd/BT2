No vulnerability found for this question.

The reported issue is a configuration/deployment defect: a runtime sets an absurdly high `forceCancelCooldown` constant at genesis, making a force-unlock function practically unusable. In `polkadot-sdk`, the closest analogs to "force-after-cooldown" patterns are all either user-configured (not hardcoded runtime defaults) or governance-adjustable:

- `polkadot/runtime/parachains/src/configuration.rs` exposes `set_validation_upgrade_cooldown` as a root-only extrinsic to change the cooldown value, and `polkadot/runtime/parachains/src/paras/mod.rs` (`remove_upgrade_cooldown`, lines 1244-1280) lets *any* signed account pay to remove an active upgrade cooldown early, explicitly designed to prevent the "cooldown makes function unusable forever" scenario described in the report. [1](#0-0) [2](#0-1) 

- `substrate/frame/recovery/src/lib.rs`'s `cancel_attempt` (lines 876-923) and `substrate/frame/registrar/para/src/lib.rs`'s `cancel_registration` (lines 493-538) use delays (`cancel_delay`, `PendingDeadline`) that are either set per-instance by the user (`set_friend_groups`) or are `Config` trait constants chosen by the runtime integrator, not values baked into a vulnerable contract with an unreachable-by-design magnitude. [3](#0-2) [4](#0-3) 

- `substrate/frame/atomic-swap/src/lib.rs`'s `cancel_swap` (lines 324-352) similarly uses a `duration` chosen by the swap creator at call time, not a protocol-wide hardcoded default. [5](#0-4) 

None of these represent a genuine code defect reachable by an unprivileged attacker; they are config-only concerns (choice of constant/parameter value), which per the audit scope's exclusion rules ("config-only... findings") is explicitly out of scope, and in every FRAME analog found there is either a governance/root path or a per-instance user-set value to adjust or bypass the delay, unlike the immutable, unreasonably large hardcoded default in the reported EVM contract.

### Citations

**File:** polkadot/runtime/parachains/src/configuration.rs (L596-610)
```rust
		/// Set the validation upgrade cooldown.
		#[pallet::call_index(0)]
		#[pallet::weight((
			T::WeightInfo::set_config_with_block_number(),
			DispatchClass::Operational,
		))]
		pub fn set_validation_upgrade_cooldown(
			origin: OriginFor<T>,
			new: BlockNumberFor<T>,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::schedule_config_update(|config| {
				config.validation_upgrade_cooldown = new;
			})
		}
```

**File:** polkadot/runtime/parachains/src/paras/mod.rs (L1244-1280)
```rust
		/// Remove an upgrade cooldown for a parachain.
		///
		/// The cost for removing the cooldown earlier depends on the time left for the cooldown
		/// multiplied by [`Config::CooldownRemovalMultiplier`]. The paid tokens are burned.
		#[pallet::call_index(9)]
		#[pallet::weight(<T as Config>::WeightInfo::remove_upgrade_cooldown())]
		pub fn remove_upgrade_cooldown(origin: OriginFor<T>, para: ParaId) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let removed = UpgradeCooldowns::<T>::mutate(|cooldowns| {
				let Some(pos) = cooldowns.iter().position(|(p, _)| p == &para) else {
					return Ok::<_, DispatchError>(false);
				};
				let (_, cooldown_until) = cooldowns.remove(pos);

				let cost = Self::calculate_remove_upgrade_cooldown_cost(cooldown_until);

				// burn...
				T::Fungible::burn_from(
					&who,
					cost,
					Preservation::Preserve,
					Precision::Exact,
					Fortitude::Polite,
				)?;

				Ok(true)
			})?;

			if removed {
				UpgradeRestrictionSignal::<T>::remove(para);

				Self::deposit_event(Event::UpgradeCooldownRemoved { para_id: para });
			}

			Ok(())
		}
```

**File:** substrate/frame/recovery/src/lib.rs (L909-915)
```rust
			if canceler != lost {
				let cancelable_at = attempt
					.last_approval_block
					.checked_add(&friend_group.cancel_delay)
					.ok_or(ArithmeticError::Overflow)?;
				ensure!(now >= cancelable_at, Error::<T>::NotYetCancelable);
			}
```

**File:** substrate/frame/registrar/para/src/lib.rs (L507-519)
```rust
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::cancel_registration())]
		pub fn cancel_registration(origin: OriginFor<T>, para_id: ParaId) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let mut info = Paras::<T>::get(para_id).ok_or(Error::<T>::NotReserved)?;
			ensure!(info.manager == who, Error::<T>::NotOwner);
			let RegistrationState::Pending { ticket, cancellable_at } = info.state else {
				return Err(Error::<T>::NotPending.into());
			};
			let now = T::BlockNumberProvider::current_block_number();
			ensure!(now >= cancellable_at, Error::<T>::CannotCancelYet);

```

**File:** substrate/frame/atomic-swap/src/lib.rs (L332-344)
```rust
		pub fn cancel_swap(
			origin: OriginFor<T>,
			target: T::AccountId,
			hashed_proof: HashedProof,
		) -> DispatchResult {
			let source = ensure_signed(origin)?;

			let swap = PendingSwaps::<T>::get(&target, hashed_proof).ok_or(Error::<T>::NotExist)?;
			ensure!(swap.source == source, Error::<T>::SourceMismatch);
			ensure!(
				frame_system::Pallet::<T>::block_number() >= swap.end_block,
				Error::<T>::DurationNotPassed,
			);
```
