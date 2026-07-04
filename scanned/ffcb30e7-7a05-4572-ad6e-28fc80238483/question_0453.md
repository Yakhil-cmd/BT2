# Q0453: Delegation Pool Switch trace drift at epoch edge

## Question
Can an unprivileged attacker enter through `switch_delegation_pool(to_staker, to_pool, amount)` in consecutive blocks before any claim in one validator with one enabled BTC-wrapper pool using a dust-sized amount just above zero and make `switch_staking_delegation_pool / enter_delegation_pool_from_staking_contract` write a future-dated checkpoint that disagrees with the actual transferred amount, so that a later balance read uses inconsistent values from `pool_member_info.unpool_amount, pool_member_info.reward_address, staking delegated traces` and breaks the intended stake-to-reward or stake-to-withdrawal invariant?

## Target
- File/function: src/pool/pool.cairo::switch_delegation_pool
- Entrypoint: switch_delegation_pool(to_staker, to_pool, amount)
- Attacker controls: caller as pool_member, to_staker, to_pool, amount, serialized switch data timing
- Exploit idea: Drive a state transition through `switch_delegation_pool(to_staker, to_pool, amount)`, then immediately force the next observable flow that reads the trace-backed balance, looking for an off-by-one between live token movement and the epoch-scheduled checkpoint.
- Invariant to test: A single user action must not leave the transferred amount, the latest checkpoint, and the value returned for epoch i or i+k in disagreement.
- Expected Immunefi impact: Medium - Material reward or staking-power accounting drift causing insolvency or unfair payouts
- Fast validation: Snforge sequence: perform `switch_delegation_pool(to_staker, to_pool, amount)` under the stated timing, query the next effective balance path, and assert that the trace-derived amount matches the actual token delta and the next reward or withdrawal computation.
