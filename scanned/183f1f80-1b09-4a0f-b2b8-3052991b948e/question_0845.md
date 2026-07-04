# Q0845: Delegation Exit Intent state-machine desync

## Question
Can an unprivileged attacker enter through `exit_delegation_pool_intent(amount)` after a zeroing update that clears one side of the state machine in a validator with both STRK and BTC-wrapper pools using a dust-sized amount just above zero and make the pending-intent state in `pool_member_info.unpool_amount, pool_member_info.unpool_time, pool_member_epoch_balance` diverge from the balance state, so that one path thinks funds are still live while another path treats them as already removed or already withdrawn?

## Target
- File/function: src/pool/pool.cairo::exit_delegation_pool_intent
- Entrypoint: exit_delegation_pool_intent(amount)
- Attacker controls: caller as pool member, amount, repeated partial intents, timing around staker unstake
- Exploit idea: Exercise partial intent replacement, zero-amount clearing, and the nearest action or switch flow until the intent amount, live balance, and transferred amount no longer describe the same funds.
- Invariant to test: For every member or staker, the live balance plus pending-exit amount must equal the previously funded position, and no exit amount should be spendable twice.
- Expected Immunefi impact: Critical - Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Run the full intent -> replacement -> action or switch sequence and assert that the final withdrawn amount plus remaining balance never exceeds the funded amount.
