# Q2907: Delegator Reward-Address Rollover address-alias edge

## Question
Can an unprivileged attacker enter through `change_reward_address(reward_address)` when the reward address is later reused by a different participant immediately after a claim and make authorization or beneficiary selection over `pool_member_info.reward_address, reward_checkpoint` resolve to a stale alias, causing funds or rewards to be claimed by the wrong live participant or frozen behind a stale mapping?

## Target
- File/function: src/pool/pool.cairo::change_reward_address
- Entrypoint: change_reward_address(reward_address)
- Attacker controls: caller, new reward_address, timing relative to claim and switch operations
- Exploit idea: Drive the address rotation or aliasing sequence and then attempt the nearest claim, top-up, or operator-driven flow from both the old and new address perspectives.
- Invariant to test: At any point in time there should be exactly one live authorized beneficiary or operator for each reward stream and operational slot.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Script the aliasing sequence and assert that only the intended current address can move value, and that value remains claimable after the rollover.
