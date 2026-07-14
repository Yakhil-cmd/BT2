# Q830: pool-plotnft via PoolAbsorbRewards 830

## Question
Can an unprivileged attacker entering through the pool login link action in `PoolAbsorbRewards` (packages/gui/src/components/pool/PoolAbsorbRewards.tsx) control fee/reward amount near precision boundary after a profile switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolAbsorbRewards.tsx` / `PoolAbsorbRewards`
- Entrypoint: pool login link action
- Attacker controls: fee/reward amount near precision boundary; after a profile switch
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
