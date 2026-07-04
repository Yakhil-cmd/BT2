# Q0388: Delegation Exit Intent trace drift at epoch edge

## Question
Can an unprivileged attacker enter through `exit_delegation_pool_intent(amount)` after one state-changing call already wrote a future-dated checkpoint in one validator with one STRK delegation pool using an amount that empties the live balance except for one unit and make `undelegate_from_staking_contract_intent / set_member_balance` write a future-dated checkpoint that disagrees with the actual transferred amount, so that a later balance read uses inconsistent values from `pool_member_info.unpool_amount, pool_member_info.unpool_time, pool_member_epoch_balance` and breaks the intended stake-to-reward or stake-to-withdrawal invariant?

## Target
- File/function: src/pool/pool.cairo::exit_delegation_pool_intent
- Entrypoint: exit_delegation_pool_intent(amount)
- Attacker controls: caller as pool member, amount, repeated partial intents, timing around staker unstake
- Exploit idea: Drive a state transition through `exit_delegation_pool_intent(amount)`, then immediately force the next observable flow that reads the trace-backed balance, looking for an off-by-one between live token movement and the epoch-scheduled checkpoint.
- Invariant to test: A single user action must not leave the transferred amount, the latest checkpoint, and the value returned for epoch i or i+k in disagreement.
- Expected Immunefi impact: Medium - Material reward or staking-power accounting drift causing insolvency or unfair payouts
- Fast validation: Snforge sequence: perform `exit_delegation_pool_intent(amount)` under the stated timing, query the next effective balance path, and assert that the trace-derived amount matches the actual token delta and the next reward or withdrawal computation.
