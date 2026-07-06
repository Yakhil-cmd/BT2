### Title
Single-Step Reward Address Change Without New-Address Confirmation Allows Permanent Loss of Unclaimed Yield - (File: src/staking/staking.cairo, src/pool/pool.cairo)

---

### Summary

Both the `Staking` and `Pool` contracts allow a staker or pool member to redirect all future reward payments to an arbitrary new address in a single transaction, with no confirmation required from the new address. A typo or accidental zero-address entry immediately takes effect, and any rewards claimed before the mistake is corrected are permanently lost. The protocol already applies a two-step pattern to `change_operational_address` (via `declare_operational_address`), making the absence of the same protection for reward addresses an inconsistent and exploitable design gap.

---

### Finding Description

`change_reward_address` in `src/staking/staking.cairo` immediately overwrites the stored `reward_address` for the calling staker in a single step:

```cairo
staker_info.reward_address = reward_address;
self.write_staker_info(:staker_address, :staker_info);
```

The only guard is that the new address must not be a registered token address. There is no check against the zero address, no pending-acceptance state, and no confirmation call required from the new address. [1](#0-0) 

The identical pattern exists in the `Pool` contract for pool members: [2](#0-1) 

By contrast, `change_operational_address` enforces a two-step flow: the candidate address must first call `declare_operational_address` to register itself as eligible, and only then can the staker complete the change. This proves the protocol designers were aware of the two-step pattern and deliberately applied it to operational addresses, but omitted it for reward addresses. [3](#0-2) [4](#0-3) 

---

### Impact Explanation

**High — Theft / permanent freezing of unclaimed yield.**

All staking rewards are transferred to `staker_info.reward_address` at claim time (via `claim_rewards` and `unstake_action`). If a staker accidentally sets this field to the zero address or any address they do not control, every reward payment made before they notice and correct the mistake is irrecoverably lost. Because `unstake_action` automatically sends accumulated rewards to the reward address as part of the exit flow, a staker who exits while the wrong address is set loses their entire accrued yield in one transaction with no recourse. [5](#0-4) 

The same applies to pool members: `change_reward_address` in the Pool contract redirects all pool-member reward payments immediately. [6](#0-5) 

---

### Likelihood Explanation

**Medium.** Address entry errors (copy-paste mistakes, truncated hex strings, zero-address placeholders) are a well-documented class of user error in blockchain systems. The risk is elevated here because:

1. The protocol already acknowledges the danger for operational addresses and mitigates it with a two-step flow, signalling that the designers consider single-step address changes risky.
2. There is no zero-address guard on `change_reward_address`, so the most common accidental input (`0x0`) is silently accepted.
3. The damage window is bounded only by how quickly the staker notices — if `unstake_action` or `claim_rewards` is called in the same session, the loss is immediate and irreversible.

---

### Recommendation

Apply the same two-step pattern already used for `change_operational_address`:

1. Add a `declare_reward_address(staker_address)` function that the candidate address must call first, storing it as a pending reward address.
2. Modify `change_reward_address` to only accept an address that has already declared itself for the calling staker, then clear the pending entry.

This ensures the new reward address is a live, reachable account before the change takes effect, eliminating the single-point-of-failure from a typo or zero-address entry.

---

### Proof of Concept

**Staker scenario (staking contract):**

```
1. Alice is a staker with reward_address = 0xAlice_wallet.
2. Alice intends to update her reward address to 0xNew_wallet but mistypes 0x0.
3. Alice calls: staking.change_reward_address(reward_address: 0x0)
   → No revert. staker_info.reward_address is now 0x0.
4. Alice calls: staking.unstake_intent()  (begins exit window)
5. After the exit window, Alice calls: staking.unstake_action(staker_address: Alice)
   → send_rewards_to_staker transfers all accumulated STRK rewards to 0x0.
   → Rewards are permanently burned. Alice receives only her principal.
```

**Pool member scenario (pool contract):**

```
1. Bob is a pool member with reward_address = 0xBob_wallet.
2. Bob calls: pool.change_reward_address(reward_address: 0x0)
   → No revert. pool_member_info.reward_address is now 0x0.
3. Bob calls: pool.exit_delegation_pool_intent(...)
4. After the exit window, Bob calls: pool.exit_delegation_pool_action(...)
   → Rewards are transferred to 0x0 and permanently lost.
```

Root cause — single-step write with no new-address confirmation and no zero-address guard: [7](#0-6) [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L492-495)
```text
            // Send rewards to staker's reward address.
            // It must be part of this function's flow because staker_info is about to be erased.
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
```

**File:** src/staking/staking.cairo (L517-540)
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

            // Emit event.
            self
                .emit(
                    Events::StakerRewardAddressChanged {
                        staker_address, new_address: reward_address, old_address,
                    },
                );
        }
```

**File:** src/staking/staking.cairo (L683-687)
```text
            assert!(
                self.eligible_operational_addresses.read(operational_address) == staker_address,
                "{}",
                Error::OPERATIONAL_NOT_ELIGIBLE,
            );
```

**File:** src/staking/staking.cairo (L705-722)
```text
        fn declare_operational_address(ref self: ContractState, staker_address: ContractAddress) {
            self.general_prerequisites();
            let operational_address = get_caller_address();
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_IN_USE,
            );
            assert!(
                !self.does_token_exist(token_address: operational_address),
                "{}",
                Error::OPERATIONAL_IS_TOKEN,
            );
            if self.eligible_operational_addresses.read(operational_address) == staker_address {
                return;
            }
            self.eligible_operational_addresses.write(operational_address, staker_address);
            self.emit(Events::OperationalAddressDeclared { operational_address, staker_address });
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
