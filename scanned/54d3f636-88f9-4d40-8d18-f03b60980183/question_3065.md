# Q3065: Delegation Exit Intent trace-bloat denial of service

## Question
Can an unprivileged attacker use `exit_delegation_pool_intent(amount)` to create repeated zero-near-zero replacements of pending exits in one validator with one STRK delegation pool, making the next stateful path over `pool_member_info.unpool_amount, pool_member_info.unpool_time, pool_member_epoch_balance` or `undelegate_from_staking_contract_intent / set_member_balance` consume unbounded gas and preventing normal users from claiming, exiting, or updating rewards?

## Target
- File/function: src/pool/pool.cairo::exit_delegation_pool_intent
- Entrypoint: exit_delegation_pool_intent(amount)
- Attacker controls: caller as pool member, amount, repeated partial intents, timing around staker unstake
- Exploit idea: Accumulate a large but protocol-valid trace through the public flow, then execute the nearest loop-backed function and measure whether gas grows without an effective bound.
- Invariant to test: A valid user position should remain serviceable without requiring work that grows linearly without bound in old user-controlled checkpoints.
- Expected Immunefi impact: Medium - Unbounded gas consumption
- Fast validation: Generate the stated number of checkpoints, then benchmark the next claim/update path and assert that gas remains below a defensible bound or that the call still succeeds at realistic limits.
