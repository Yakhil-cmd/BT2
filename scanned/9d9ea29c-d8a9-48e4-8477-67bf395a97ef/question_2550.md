# Q2550: pool-plotnft via usePlotNFTs 2550

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `usePlotNFTs` (packages/gui/src/hooks/usePlotNFTs.ts) control pool URL/login response with mismatched launcher ID through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePlotNFTs.ts` / `usePlotNFTs`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: pool URL/login response with mismatched launcher ID; through a batch of rapid user-accessible actions
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
