# Q1542: pool-plotnft via PlotNFTExternalState 1542

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PlotNFTExternalState` (packages/gui/src/components/plotNFT/PlotNFTExternalState.tsx) control fee/reward amount near precision boundary with hidden Unicode characters and drive the sequence load persisted state -> render approval -> execute command so the GUI would route pool login links through unsafe external URL handling, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTExternalState.tsx` / `PlotNFTExternalState`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: fee/reward amount near precision boundary; with hidden Unicode characters
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
