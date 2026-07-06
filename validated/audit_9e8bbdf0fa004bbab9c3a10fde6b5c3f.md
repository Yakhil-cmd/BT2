### Title
No Proof of Possession in `set_public_key` Enables Rogue Key Registration for Consensus Disruption — (File: src/staking/staking.cairo)

---

### Summary

The `set_public_key` function in the Staking contract allows any registered staker to register an arbitrary public key without proving ownership of the corresponding private key. This is the direct structural analog to the BLS rogue key attack: an attacker who is a staker can register a public key that is the additive inverse (negation) of a victim staker's key. When the consensus layer aggregates public keys from `get_stakers()`, the victim's contribution is cancelled, disrupting the victim's consensus participation and causing loss of consensus rewards.

---

### Finding Description

`set_public_key` performs only two checks before writing the caller-supplied key to storage:

1. The key is non-zero.
2. The key differs from the previously stored key.

There is no proof of possession — no signature or challenge-response that demonstrates the caller controls the private key corresponding to the submitted public key.

```cairo
fn set_public_key(ref self: ContractState, public_key: PublicKey) {
    self.general_prerequisites();
    assert!(public_key.is_non_zero(), "{}", Error::INVALID_PUBLIC_KEY);
    let staker_address = get_caller_address();
    let staker_info = self.internal_staker_info(:staker_address);
    assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

    let (curr_activation_epoch, _, prev_public_key) = self.public_key.read(staker_address);
    let curr_epoch = self.get_current_epoch();
    assert!(curr_epoch >= curr_activation_epoch, "{}", Error::PUBLIC_KEY_SET_IN_PROGRESS);
    assert!(prev_public_key != public_key, "{}", Error::PUBLIC_KEY_MUST_DIFFER);

    let new_activation_epoch = self.get_epoch_plus_k();
    self.public_key.write(staker_address, (new_activation_epoch, prev_public_key, public_key));
    self.emit(Events::PublicKeySet { staker_address, public_key });
}
``` [1](#0-0) 

There is also no uniqueness constraint — the existing test suite explicitly demonstrates that two independent stakers can register the identical public key and both appear in `get_stakers()` output:

```cairo
staking.set_public_key(:public_key);   // staker_1
// ...
staking.set_public_key(:public_key);   // staker_2
// Both appear with the same key in get_stakers()
``` [2](#0-1) 

The registered public keys are consumed by `get_stakers()`, which returns `(staker_address, staking_power, Option<PublicKey>, Option<PeerId>)` tuples to the consensus layer:

```cairo
let public_key = self.get_public_key_at_epoch(:staker_address, :epoch_id);
let peer_id = self.get_peer_id_at_epoch(:staker_address, :epoch_id);
stakers.append((staker_address, staking_power, public_key, peer_id));
``` [3](#0-2) 

`PublicKey` is typed as `felt252` — a prime-field element — so its additive inverse (`-pk mod p`) is a well-defined, trivially computable value. [4](#0-3) 

---

### Impact Explanation

The consensus layer receives the full staker set including public keys via `get_stakers()`. When it aggregates keys for BLS-style multi-signature verification (standard in PoS consensus), the following holds:

- Victim registers `pk_victim`.
- Attacker registers `pk_attacker = -pk_victim` (additive inverse in the field).
- Aggregate key: `pk_agg = pk_victim + pk_attacker = 0` (point at infinity).

A zero aggregate key allows the attacker to produce a valid aggregate signature over any message without possessing any private key, exactly as described in the external report. Concretely:

- The victim's consensus contribution is silently cancelled.
- The victim fails to participate in consensus for the affected epoch(s).
- The victim loses consensus rewards for at least K epochs (the mandatory delay before a corrective `set_public_key` call takes effect).

This constitutes **theft of unclaimed yield / temporary freezing of unclaimed yield** (High severity) for the victim staker.

Even absent BLS aggregation, the absence of uniqueness and proof-of-possession allows an attacker to impersonate any victim's consensus identity, constituting **griefing with damage to users** (Medium severity).

---

### Likelihood Explanation

- Entry path is fully unprivileged: any address that has called `stake()` can call `set_public_key()`.
- The victim's public key is broadcast on-chain via the `PublicKeySet` event and readable via `get_current_public_key()`.
- Computing the field negation of a `felt252` value is trivial arithmetic.
- The attack requires only the minimum stake amount and one transaction.

Likelihood is **High**.

---

### Recommendation

Require proof of possession before accepting a new public key. The staker must provide a signature over a domain-separated message (e.g., `H(staker_address || public_key || chain_id)`) produced by the private key corresponding to the submitted public key. The contract verifies this signature on-chain before writing the key to storage. This mirrors the `setSafeWallet()` pattern referenced in the external report and eliminates the rogue-key vector entirely.

Additionally, enforce a global uniqueness constraint: reject any `set_public_key` call whose submitted key is already registered to a different staker.

---

### Proof of Concept

```
1. Victim (staker_v) calls set_public_key(pk_v).
   Storage: public_key[staker_v] = (epoch+K, 0, pk_v)

2. Attacker stakes minimum amount, becoming staker_a.

3. Attacker calls set_public_key(-pk_v mod STARK_PRIME).
   Storage: public_key[staker_a] = (epoch+K, 0, -pk_v)

4. After K epochs, get_stakers(epoch_id) returns:
   [..., (staker_v, power_v, Some(pk_v), ...), (staker_a, power_a, Some(-pk_v), ...), ...]

5. Consensus layer computes aggregate key:
   pk_agg = ... + pk_v + (-pk_v) + ... = (sum of all other keys)
   The victim's key contributes zero to the aggregate.

6. Attacker can produce a valid aggregate signature without the victim's private key,
   forging consensus participation on behalf of the victim.

7. Victim's consensus rewards are lost for at least K epochs.
   Victim must call set_public_key again (another K-epoch delay) to recover.
```

### Citations

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

**File:** src/staking/staking.cairo (L932-934)
```text
                let public_key = self.get_public_key_at_epoch(:staker_address, :epoch_id);
                let peer_id = self.get_peer_id_at_epoch(:staker_address, :epoch_id);
                stakers.append((staker_address, staking_power, public_key, peer_id));
```

**File:** src/flow_test/test.cairo (L1861-1883)
```text
    cheat_caller_address_once(
        contract_address: staking_address, caller_address: staker_1.staker.address,
    );
    staking.set_public_key(:public_key);

    // Staker 2 stake and set public key.
    system.stake(staker: staker_2, :amount, pool_enabled: false, commission: 200);
    cheat_caller_address_once(
        contract_address: staking_address, caller_address: staker_2.staker.address,
    );
    staking.set_public_key(:public_key);

    // Test get_stakers.
    system.advance_k_epochs();
    let expected_stakers = array![
        (staker_1.staker.address, STRK_WEIGHT_FACTOR / 2, Option::Some(public_key), Option::None),
        (staker_2.staker.address, STRK_WEIGHT_FACTOR / 2, Option::Some(public_key), Option::None),
    ]
        .span();
    let epoch_id = staking.get_current_epoch();
    assert!(staking_consensus.get_stakers(:epoch_id) == expected_stakers);
    assert!(staking.get_current_public_key(staker_address: staker_1.staker.address) == public_key);
    assert!(staking.get_current_public_key(staker_address: staker_2.staker.address) == public_key);
```

**File:** src/types.cairo (L12-12)
```text
pub type PublicKey = felt252;
```
