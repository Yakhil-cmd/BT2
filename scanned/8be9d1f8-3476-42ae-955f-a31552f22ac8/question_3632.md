# Q3632: pool-plotnft via handleAbsorbRewards 3632

## Question
Can an unprivileged attacker entering through the pool join/change flow in `handleAbsorbRewards` (packages/gui/src/components/pool/PoolAbsorbRewards.tsx) control external pool metadata changing between preview and submit with a stale Redux cache and drive the sequence load persisted state -> render approval -> execute command so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolAbsorbRewards.tsx` / `handleAbsorbRewards`
- Entrypoint: pool join/change flow
- Attacker controls: external pool metadata changing between preview and submit; with a stale Redux cache
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
