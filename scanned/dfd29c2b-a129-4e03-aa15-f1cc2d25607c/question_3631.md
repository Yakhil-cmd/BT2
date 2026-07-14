# Q3631: pool-plotnft via Pool 3631

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `Pool` (packages/gui/src/components/pool/Pool.tsx) control external pool metadata changing between preview and submit during a pending modal confirmation and drive the sequence fetch -> cache -> refresh -> submit so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/Pool.tsx` / `Pool`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: external pool metadata changing between preview and submit; during a pending modal confirmation
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
