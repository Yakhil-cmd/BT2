# Q680: pool-plotnft via usePlotNFTDetails 680

## Question
Can an unprivileged attacker entering through the payout instruction update in `usePlotNFTDetails` (packages/gui/src/hooks/usePlotNFTDetails.ts) control fee/reward amount near precision boundary with hidden Unicode characters and drive the sequence download or render content -> trigger linked wallet action so the GUI would route pool login links through unsafe external URL handling, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTDetails.ts` / `usePlotNFTDetails`
- Entrypoint: payout instruction update
- Attacker controls: fee/reward amount near precision boundary; with hidden Unicode characters
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
