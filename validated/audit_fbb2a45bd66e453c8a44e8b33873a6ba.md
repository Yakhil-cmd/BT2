### Title
No Global Uniqueness Enforcement on `public_key` Allows Duplicate Consensus Keys Across Stakers - (File: `src/staking/staking.cairo`)

---

### Summary
The `set_public_key` function in `staking.cairo` only checks that the new key differs from the calling staker's own previous key. There is no global reverse-mapping to enforce that a `public_key` is unique across all registered stakers. Any active staker can register the same `public_key` already in use by a legitimate staker. The `get_stakers` function then surfaces duplicate public keys to the consensus layer, which can cause the legitimate staker to be excluded from block production and lose consensus rewards.

---

### Finding Description

`set_public_key` performs two checks before writing:

1. The caller is an active staker with no unstake in progress.
2. The new key differs from the staker's own previous key (`prev_public_key != public_key`). [1](#0-0) 

There is no storage structure analogous to `operational_address_to_staker_address` (which enforces 1-to-1 uniqueness for operational addresses) for `public_key`. The storage layout confirms this: `public_key` is a `Map<ContractAddress, (Epoch, PublicKey, PublicKey)>` keyed only by staker address, with no reverse index. [2](#0-1) 

Compare with the operational address, which has an explicit reverse mapping: [3](#0-2) 

`get_stakers` iterates over all active stakers and appends each staker's `(address, staking_power, public_key, peer_id)` tuple to the output without any deduplication check: [4](#0-3) 

If two stakers share the same `public_key`, the consensus layer receives two entries with identical keys, one of which belongs to the malicious staker.

---

### Impact Explanation

**Medium — Griefing with damage to users.**

A malicious staker observes a high-stake legitimate staker's public key (emitted via `PublicKeySet` event or read from `get_stakers`) and calls `set_public_key` with that same value. The consensus layer then sees two validator entries with the same public key. Depending on consensus layer behavior, the legitimate staker's entry may be rejected or shadowed, preventing them from producing blocks and earning consensus rewards. The attacker gains nothing financially; the damage is entirely to the legitimate staker's ability to earn future yield.

---

### Likelihood Explanation

**Low-Medium.** Any registered staker (minimum stake required) can execute this. The target public key is publicly observable on-chain via the `PublicKeySet` event or `get_stakers`. The attacker must be a registered staker but needs no privileged access. The attack is repeatable: each time the victim rotates their key, the attacker can copy it again after the `K`-epoch activation delay passes.

---

### Recommendation

Introduce a global reverse mapping `public_key_to_staker: Map<PublicKey, ContractAddress>` (mirroring the pattern used for `operational_address_to_staker_address`) and assert uniqueness in `set_public_key`:

```cairo
assert!(
    self.public_key_to_staker.read(public_key).is_zero(),
    "{}",
    Error::PUBLIC_KEY_ALREADY_IN_USE,
);
// Clear old reverse mapping, write new one.
self.public_key_to_staker.write(prev_public_key, Zero::zero());
self.public_key_to_staker.write(public_key, staker_address);
```

Apply the same pattern to `set_peer_id`.

---

### Proof of Concept

1. Legitimate staker `A` calls `set_public_key(pk_A)`. Event `PublicKeySet { staker_address: A, public_key: pk_A }` is emitted.
2. After the `K`-epoch activation window, `pk_A` becomes `A`'s active key and appears in `get_stakers`.
3. Malicious staker `M` (any registered staker) calls `set_public_key(pk_A)`. The only check is `prev_public_key_of_M != pk_A`, which passes since `M` has a different previous key.
4. After `K` epochs, `get_stakers` returns both `(A, power_A, Some(pk_A), ...)` and `(M, power_M, Some(pk_A), ...)`.
5. The consensus layer receives two entries with `public_key = pk_A`. Staker `A` may be excluded from block production, losing consensus rewards indefinitely until they rotate to a new key — at which point `M` can repeat the attack. [5](#0-4) [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L123-126)
```text
        /// Map operational address to staker address, as it must be a 1 to 1 mapping.
        operational_address_to_staker_address: Map<ContractAddress, ContractAddress>,
        /// Map potential operational address to eligible staker address.
        eligible_operational_addresses: Map<ContractAddress, ContractAddress>,
```

**File:** src/staking/staking.cairo (L172-181)
```text
        /// Map staker address to (activation_epoch, old_public_key, new_public_key).
        /// Similarily to `btc_tokens`, the `activation_epoch` is the first epoch from
        /// which the `new_public_key` is valid. Up until `activation_epoch`, the
        /// `old_public_key` is valid.
        public_key: Map<ContractAddress, (Epoch, PublicKey, PublicKey)>,
        /// Map staker address to (activation_epoch, old_peer_id, new_peer_id).
        /// Similarly to `public_key`, the `activation_epoch` is the first epoch from
        /// which the `new_peer_id` is valid. Up until `activation_epoch`, the
        /// `old_peer_id` is valid.
        peer_id: Map<ContractAddress, (Epoch, PeerId, PeerId)>,
```

**File:** src/staking/staking.cairo (L834-852)
```text
        fn set_public_key(ref self: ContractState, public_key: PublicKey) {
            self.general_prerequisites();
            assert!(public_key.is_non_zero(), "{}", Error::INVALID_PUBLIC_KEY);
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

            let (curr_activation_epoch, _, prev_public_key) = self.public_key.read(staker_address);
            let curr_epoch = self.get_current_epoch();
            // TODO: Confirm with product this set period is ok.
            assert!(curr_epoch >= curr_activation_epoch, "{}", Error::PUBLIC_KEY_SET_IN_PROGRESS);
            assert!(prev_public_key != public_key, "{}", Error::PUBLIC_KEY_MUST_DIFFER);

            let new_activation_epoch = self.get_epoch_plus_k();
            self
                .public_key
                .write(staker_address, (new_activation_epoch, prev_public_key, public_key));
            self.emit(Events::PublicKeySet { staker_address, public_key });
        }
```

**File:** src/staking/staking.cairo (L901-937)
```text
        fn get_stakers(
            self: @ContractState, epoch_id: Epoch,
        ) -> Span<(ContractAddress, StakingPower, Option<PublicKey>, Option<PeerId>)> {
            let curr_epoch = self.get_current_epoch();
            assert!(
                curr_epoch <= epoch_id && epoch_id < curr_epoch + K.into(),
                "{}",
                Error::INVALID_EPOCH,
            );

            let (strk_total_stake, btc_total_stake) = self
                .get_total_staking_power_at_epoch(:epoch_id);

            let mut stakers: Array<
                (ContractAddress, StakingPower, Option<PublicKey>, Option<PeerId>),
            > =
                array![];
            for staker_address_ptr in self.stakers.into_iter_full_range() {
                let staker_address = staker_address_ptr.read();
                if !self.is_staker_active(:staker_address, :epoch_id) {
                    continue;
                }

                let staking_power = self
                    .get_staker_staking_power_at_epoch(
                        :staker_address, :epoch_id, :strk_total_stake, :btc_total_stake,
                    );
                if staking_power.is_zero() {
                    continue;
                }

                let public_key = self.get_public_key_at_epoch(:staker_address, :epoch_id);
                let peer_id = self.get_peer_id_at_epoch(:staker_address, :epoch_id);
                stakers.append((staker_address, staking_power, public_key, peer_id));
            }
            stakers.span()
        }
```
