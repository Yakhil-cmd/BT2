# Q2863: Delegation Top-Up address-alias edge

## Question
Can an unprivileged attacker enter through `add_to_delegation_pool(pool_member, amount)` when the reward address is the same as another active reward address between two claims in the same epoch and make authorization or beneficiary selection over `pool_member_info, pool_member_epoch_balance, staking delegated balance` resolve to a stale alias, causing funds or rewards to be claimed by the wrong live participant or frozen behind a stale mapping?

## Target
- File/function: src/pool/pool.cairo::add_to_delegation_pool
- Entrypoint: add_to_delegation_pool(pool_member, amount)
- Attacker controls: caller as pool_member or reward_address, chosen pool_member, amount, add timing
- Exploit idea: Drive the address rotation or aliasing sequence and then attempt the nearest claim, top-up, or operator-driven flow from both the old and new address perspectives.
- Invariant to test: At any point in time there should be exactly one live authorized beneficiary or operator for each reward stream and operational slot.
- Expected Immunefi impact: High - Theft of unclaimed yield
- Fast validation: Script the aliasing sequence and assert that only the intended current address can move value, and that value remains claimable after the rollover.
