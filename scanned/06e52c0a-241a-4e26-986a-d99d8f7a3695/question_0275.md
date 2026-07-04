# Q0275: Delegation Top-Up trace drift at epoch edge

## Question
Can an unprivileged attacker enter through `add_to_delegation_pool(pool_member, amount)` across the i to i+k latency boundary in one validator with one STRK delegation pool using an amount split across many micro-transactions and make `increase_member_balance / transfer_to_staking_contract` write a future-dated checkpoint that disagrees with the actual transferred amount, so that a later balance read uses inconsistent values from `pool_member_info, pool_member_epoch_balance, staking delegated balance` and breaks the intended stake-to-reward or stake-to-withdrawal invariant?

## Target
- File/function: src/pool/pool.cairo::add_to_delegation_pool
- Entrypoint: add_to_delegation_pool(pool_member, amount)
- Attacker controls: caller as pool_member or reward_address, chosen pool_member, amount, add timing
- Exploit idea: Drive a state transition through `add_to_delegation_pool(pool_member, amount)`, then immediately force the next observable flow that reads the trace-backed balance, looking for an off-by-one between live token movement and the epoch-scheduled checkpoint.
- Invariant to test: A single user action must not leave the transferred amount, the latest checkpoint, and the value returned for epoch i or i+k in disagreement.
- Expected Immunefi impact: Medium - Material reward or staking-power accounting drift causing insolvency or unfair payouts
- Fast validation: Snforge sequence: perform `add_to_delegation_pool(pool_member, amount)` under the stated timing, query the next effective balance path, and assert that the trace-derived amount matches the actual token delta and the next reward or withdrawal computation.
