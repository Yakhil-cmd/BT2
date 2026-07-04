# Q1135: Public consensus reward suppression

## Question
Can an unprivileged attacker call `update_rewards(staker_address, disable_rewards)` and, because the caller updates a validator whose BTC-wrapper balance is changing across the epoch boundary after the victim already accrued but before they claim against a validator with only BTC-wrapper delegation, abuse the public `disable_rewards` flag or the global `last_reward_block` gate to suppress or redirect block rewards that should have been attributed elsewhere?

## Target
- File/function: src/staking/staking.cairo::update_rewards
- Entrypoint: update_rewards(staker_address, disable_rewards)
- Attacker controls: arbitrary caller, chosen staker_address, caller-chosen disable_rewards flag, per-block call ordering
- Exploit idea: Use arbitrary-caller access to choose both `staker_address` and `disable_rewards`, then test whether updating the wrong target first for a block permanently discards that block's rewards or starves the intended staker.
- Invariant to test: A public reward update path must not let an unrelated caller zero out or monopolize a rewardable block for another active validator.
- Expected Immunefi impact: High - Permanent freezing of unclaimed yield
- Fast validation: Stand up at least two active validators, alternate benign and hostile callers over many blocks, and compare the observed cumulative rewards against a model where each eligible validator receives its intended block reward opportunity.
