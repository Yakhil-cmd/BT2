### Title
`change_reward_address` in Pool Checks Wrong Token Address, Allowing STRK Reward Token to Be Set as Reward Destination in Non-STRK Pools — (`src/pool/pool.cairo`)

---

### Summary

The `change_reward_address` guard in `pool.cairo` only validates that the new reward address is not the pool's own **staking token** (e.g., BTC). However, pool rewards are always disbursed in **STRK** (hardcoded). For any non-STRK pool (e.g., a BTC delegation pool), a pool member can freely set their `reward_address` to `STRK_TOKEN_ADDRESS`. When `claim_rewards` is subsequently called, the STRK reward transfer is sent to the STRK token contract itself, permanently freezing those rewards.

---

### Finding Description

`change_reward_address` in `pool.cairo` performs this guard:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
``` [1](#0-0) 

`self.token_dispatcher.contract_address` is the pool's **staking token** — for a BTC pool this is the BTC token address, not STRK. The guard therefore only blocks setting the reward address to the BTC token contract. It does **not** block setting it to `STRK_TOKEN_ADDRESS`.

Meanwhile, `claim_rewards` always pays out in STRK, hardcoded:

```cairo
let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [2](#0-1) 

`STRK_TOKEN_ADDRESS` is a compile-time constant: [3](#0-2) 

So the guard checks the wrong token. The token that matters for reward delivery is STRK, but the guard only checks the pool's staking token. This is the direct analog of M-06: the wrong address is used in the protective check.

---

### Impact Explanation

A BTC pool member who sets `reward_address = STRK_TOKEN_ADDRESS` will cause every subsequent `claim_rewards` call to transfer STRK into the STRK token contract itself. ERC-20 contracts have no withdrawal mechanism for tokens sent to their own address; those STRK rewards are permanently frozen. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

Any pool member in any non-STRK pool (e.g., BTC pool) can call `change_reward_address(STRK_TOKEN_ADDRESS)` directly. No privileged access is required. The call passes the guard because `STRK_TOKEN_ADDRESS != BTC_TOKEN_ADDRESS`. The member (or a griefing attacker who controls the pool member key) can then trigger `claim_rewards`, permanently destroying the accumulated STRK yield for that member. [4](#0-3) 

---

### Recommendation

The guard in `change_reward_address` must also reject `STRK_TOKEN_ADDRESS` (the reward token), not only the pool's staking token:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    assert!(
        STRK_TOKEN_ADDRESS != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
```

Alternatively, consolidate into a single check covering all protocol-controlled token addresses. The same audit should be applied to `enter_delegation_pool` to ensure the initial `reward_address` supplied at pool entry is subject to the same validation.

---

### Proof of Concept

1. A BTC delegation pool is deployed for a staker via `set_open_for_delegation(btc_token_address)`.
2. A pool member calls `enter_delegation_pool(reward_address: any_valid_address, amount: X)` on the BTC pool.
3. The pool member calls `change_reward_address(reward_address: STRK_TOKEN_ADDRESS)`.
   - Guard passes: `BTC_TOKEN_ADDRESS != STRK_TOKEN_ADDRESS` ✓
4. Epochs advance; rewards accumulate.
5. Anyone calls `claim_rewards(pool_member)`.
   - `reward_token.checked_transfer(recipient: STRK_TOKEN_ADDRESS, amount: rewards)` executes.
   - STRK rewards are transferred into the STRK token contract and are permanently unrecoverable. [5](#0-4) [6](#0-5)

### Citations

**File:** src/pool/pool.cairo (L335-377)
```text
        fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            let until_checkpoint = self.get_current_checkpoint(:pool_member);

            // Calculate rewards and update entry_to_claim_from.
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardClaimed {
                        pool_member, reward_address, amount: rewards,
                    },
                );

            rewards
        }
```

**File:** src/pool/pool.cairo (L505-526)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let old_address = pool_member_info.reward_address;

            // Update reward_address and commit to storage.
            pool_member_info.reward_address = reward_address;
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardAddressChanged {
                        pool_member, new_address: reward_address, old_address,
                    },
                );
        }
```

**File:** src/constants.cairo (L1-21)
```text
use staking::types::{Amount, Epoch};
use starknet::ContractAddress;

pub(crate) const STRK_IN_FRIS: Amount = 1_000_000_000_000_000_000; // 10**18

pub(crate) const STARTING_EPOCH: Epoch = 0;
pub(crate) const STRK_TOKEN_ADDRESS: ContractAddress =
    0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d
    .try_into()
    .unwrap();

/// Epoch delay before consensus-related changes (e.g. balances, token activations) take effect.
pub(crate) const K: u8 = 2;

/// Fractional weight for BTC relative to total (STRK+BTC), scaled by `ALPHA_DENOMINATOR`.
pub(crate) const ALPHA: u128 = 25;
/// Denominator used to scale `ALPHA` when computing BTC and STRK weights.
pub(crate) const ALPHA_DENOMINATOR: u128 = 100;

/// Number of seconds in one year.
pub(crate) const SECONDS_IN_YEAR: u64 = 365 * 24 * 60 * 60;
```
