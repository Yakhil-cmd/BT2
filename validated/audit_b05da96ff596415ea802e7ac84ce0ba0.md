### Title
Front-Running `change_reward_address` Allows Old Reward Address to Steal Accumulated Unclaimed Yield - (File: `src/pool/pool.cairo`, `src/staking/staking.cairo`)

---

### Summary
Both the delegation pool and staking contracts allow a reward address to be changed without first flushing accumulated unclaimed rewards. Because `claim_rewards` authorizes the **current** reward address at call time, a malicious old reward address can observe a pending `change_reward_address` transaction in the mempool and front-run it with `claim_rewards`, draining all accumulated yield before the address change takes effect. This is the direct analog of the ERC20 approve/transferFrom race condition described in the external report.

---

### Finding Description

**In `pool.cairo`**, `change_reward_address` simply overwrites the stored `reward_address` field without claiming pending rewards:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    let pool_member = get_caller_address();
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    // No claim of accumulated rewards here
    pool_member_info.reward_address = reward_address;
    self.write_pool_member_info(:pool_member, :pool_member_info);
    ...
}
``` [1](#0-0) 

`claim_rewards` authorizes both the pool member **and the current reward address** to trigger a payout, and sends funds to whichever address is stored at call time:

```cairo
fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
    let reward_address = pool_member_info.reward_address;
    assert!(
        caller_address == pool_member || caller_address == reward_address, ...
    );
    ...
    reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [2](#0-1) 

The identical pattern exists in the staking contract: [3](#0-2) [4](#0-3) [5](#0-4) 

---

### Impact Explanation

A malicious old reward address can steal all accumulated unclaimed yield that the pool member/staker intended to redirect to a new address. This maps directly to **"Theft of unclaimed yield"** (High severity).

---

### Likelihood Explanation

The attack is realistic whenever the reward address is a third-party entity (a yield aggregator contract, a custodial service, a multisig, or any address not fully controlled by the staker). Such parties can monitor the public Starknet mempool for `change_reward_address` calls and submit a competing `claim_rewards` transaction. The Starknet sequencer processes transactions in submission order, so a front-runner who submits before the address-change transaction is confirmed will succeed. No privileged access is required beyond having previously been set as the reward address.

---

### Recommendation

1. **Atomically flush rewards on address change**: Inside `change_reward_address` (both in `pool.cairo` and `staking.cairo`), claim and transfer any accumulated rewards to the **old** reward address before overwriting the field. This eliminates the race window entirely.
2. **Alternatively**, require `unclaimed_rewards == 0` before allowing a reward-address change, forcing the caller to explicitly claim first.
3. Document the race condition prominently so integrators know to call `claim_rewards` before `change_reward_address`.

---

### Proof of Concept

**Pool contract scenario:**

1. Alice (pool member) has `reward_address = Bob` and has accumulated rewards `R > 0` in the pool's cumulative sigma index.
2. Alice submits `pool.change_reward_address(Carol)` to redirect future rewards to Carol.
3. Bob monitors the mempool, sees Alice's pending transaction, and immediately submits `pool.claim_rewards(Alice)`.
4. Bob's transaction is sequenced first. At that moment `pool_member_info.reward_address == Bob`, so Bob passes the authorization check and receives `R` STRK tokens. [6](#0-5) 
5. Alice's `change_reward_address(Carol)` is then processed; `reward_address` is now Carol.
6. Alice calls `claim_rewards(Alice)` — the calculated reward is `0` because the checkpoint was already advanced in step 4. [7](#0-6) 

**Net result:** Bob extracted `R` tokens that Alice intended for Carol. The same sequence applies to the staking contract's `change_reward_address` / `claim_rewards` pair. [8](#0-7)

### Citations

**File:** src/pool/pool.cairo (L335-366)
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

**File:** src/staking/staking.cairo (L411-431)
```text
        fn claim_rewards(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let caller_address = get_caller_address();
            let reward_address = staker_info.reward_address;
            assert!(
                caller_address == staker_address || caller_address == reward_address,
                "{}",
                Error::CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            // Transfer rewards to staker's reward address and write updated staker info to storage.
            // Note: `send_rewards_to_staker` alters `staker_info` thus commit to storage is
            // performed only after that.
            let amount = staker_info.unclaimed_rewards_own;
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            self.write_staker_info(:staker_address, :staker_info);
            amount
        }
```

**File:** src/staking/staking.cairo (L517-531)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            let staker_address = get_caller_address();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let old_address = staker_info.reward_address;

            // Update reward_address and commit to storage.
            staker_info.reward_address = reward_address;
            self.write_staker_info(:staker_address, :staker_info);
```

**File:** src/staking/staking.cairo (L1614-1628)
```text
        fn send_rewards_to_staker(
            ref self: ContractState,
            staker_address: ContractAddress,
            ref staker_info: InternalStakerInfoLatest,
            token_dispatcher: IERC20Dispatcher,
        ) {
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();

            self.emit(Events::StakerRewardClaimed { staker_address, reward_address, amount });
```
