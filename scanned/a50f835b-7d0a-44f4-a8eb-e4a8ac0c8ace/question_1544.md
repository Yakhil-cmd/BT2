# Q1544: pool-plotnft via if 1544

## Question
Can an unprivileged attacker entering through the payout instruction update in `if` (packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx) control payout address with network or Unicode ambiguity through a batch of rapid user-accessible actions and drive the sequence preview -> mutate controlled state -> confirm so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx` / `if`
- Entrypoint: payout instruction update
- Attacker controls: payout address with network or Unicode ambiguity; through a batch of rapid user-accessible actions
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
