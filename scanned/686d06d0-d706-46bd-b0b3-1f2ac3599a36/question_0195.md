# Q0195: Initial Delegation Into A Pool trace drift at epoch edge

## Question
Can an unprivileged attacker enter through `enter_delegation_pool(reward_address, amount)` across the i to i+k latency boundary in one validator with one STRK delegation pool using an amount split across many micro-transactions and make `set_member_balance / transfer_to_staking_contract` write a future-dated checkpoint that disagrees with the actual transferred amount, so that a later balance read uses inconsistent values from `pool_member_info, pool_member_epoch_balance, cumulative_rewards_trace` and breaks the intended stake-to-reward or stake-to-withdrawal invariant?

## Target
- File/function: src/pool/pool.cairo::enter_delegation_pool
- Entrypoint: enter_delegation_pool(reward_address, amount)
- Attacker controls: caller as delegator, reward_address, amount, token type of the pool, join timing
- Exploit idea: Drive a state transition through `enter_delegation_pool(reward_address, amount)`, then immediately force the next observable flow that reads the trace-backed balance, looking for an off-by-one between live token movement and the epoch-scheduled checkpoint.
- Invariant to test: A single user action must not leave the transferred amount, the latest checkpoint, and the value returned for epoch i or i+k in disagreement.
- Expected Immunefi impact: Medium - Material reward or staking-power accounting drift causing insolvency or unfair payouts
- Fast validation: Snforge sequence: perform `enter_delegation_pool(reward_address, amount)` under the stated timing, query the next effective balance path, and assert that the trace-derived amount matches the actual token delta and the next reward or withdrawal computation.
