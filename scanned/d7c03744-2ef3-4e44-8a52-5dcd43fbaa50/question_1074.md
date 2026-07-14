# Q1074: pool-plotnft via PlotNFTExternal 1074

## Question
Can an unprivileged attacker entering through the pool join/change flow in `PlotNFTExternal` (packages/api/src/@types/PlotNFTExternal.ts) control stale PlotNFT wallet id during pool change after canceling and reopening the dialog and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/PlotNFTExternal.ts` / `PlotNFTExternal`
- Entrypoint: pool join/change flow
- Attacker controls: stale PlotNFT wallet id during pool change; after canceling and reopening the dialog
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
