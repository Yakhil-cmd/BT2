# Q0951: Delegation Pool Switch state-machine desync

## Question
Can an unprivileged attacker enter through `switch_delegation_pool(to_staker, to_pool, amount)` while the validator is between unstake intent and unstake action in a validator with one BTC-wrapper pool using an amount split across many micro-transactions and make the pending-intent state in `pool_member_info.unpool_amount, pool_member_info.reward_address, staking delegated traces` diverge from the balance state, so that one path thinks funds are still live while another path treats them as already removed or already withdrawn?

## Target
- File/function: src/pool/pool.cairo::switch_delegation_pool
- Entrypoint: switch_delegation_pool(to_staker, to_pool, amount)
- Attacker controls: caller as pool_member, to_staker, to_pool, amount, serialized switch data timing
- Exploit idea: Exercise partial intent replacement, zero-amount clearing, and the nearest action or switch flow until the intent amount, live balance, and transferred amount no longer describe the same funds.
- Invariant to test: For every member or staker, the live balance plus pending-exit amount must equal the previously funded position, and no exit amount should be spendable twice.
- Expected Immunefi impact: Critical - Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Run the full intent -> replacement -> action or switch sequence and assert that the final withdrawn amount plus remaining balance never exceeds the funded amount.
