Looking at the `assignStakingRewards` and `assignStakingRewardsFlex` functions in `kaiax/reward/impl/getter.go`, I can identify a direct analog to the WooPPV2 "same entity on both sides" bug.

Let me verify the `Split` function and `FinalizeState` distribution path: