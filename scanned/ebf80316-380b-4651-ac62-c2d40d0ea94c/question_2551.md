# Q2551: pool-plotnft via usePoolInfo 2551

## Question
Can an unprivileged attacker entering through the payout instruction update in `usePoolInfo` (packages/gui/src/hooks/usePoolInfo.ts) control payout address with network or Unicode ambiguity through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePoolInfo.ts` / `usePoolInfo`
- Entrypoint: payout instruction update
- Attacker controls: payout address with network or Unicode ambiguity; through a batch of rapid user-accessible actions
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
