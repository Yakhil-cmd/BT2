# Q2745: pool-plotnft via groupsOptions 2745

## Question
Can an unprivileged attacker entering through the pool login link action in `groupsOptions` (packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx) control stale PlotNFT wallet id during pool change with case-normalized identifiers and drive the sequence select -> edit backing object -> submit so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx` / `groupsOptions`
- Entrypoint: pool login link action
- Attacker controls: stale PlotNFT wallet id during pool change; with case-normalized identifiers
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
