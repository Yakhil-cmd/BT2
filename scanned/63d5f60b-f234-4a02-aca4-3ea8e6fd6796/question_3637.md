# Q3637: pool-plotnft via PoolOverview 3637

## Question
Can an unprivileged attacker entering through the pool join/change flow in `PoolOverview` (packages/gui/src/components/pool/PoolOverview.tsx) control external pool metadata changing between preview and submit after canceling and reopening the dialog and drive the sequence import -> parse -> preview -> submit so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolOverview.tsx` / `PoolOverview`
- Entrypoint: pool join/change flow
- Attacker controls: external pool metadata changing between preview and submit; after canceling and reopening the dialog
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
