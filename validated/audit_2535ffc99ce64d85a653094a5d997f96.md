Looking at the `update_rewards` function in `src/staking/staking.cairo` and comparing it to the spec's stated access control, I can identify a valid analog.

The spec at `docs/spec.md` line 1644-1645 states:
> **access control**: Only starkware sequencer.

But the implementation has no such check. Let me verify the exact code path.