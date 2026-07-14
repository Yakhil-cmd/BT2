# Q2418: pool-plotnft via PlotNFT 2418

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PlotNFT` (packages/api/src/@types/PlotNFT.ts) control stale PlotNFT wallet id during pool change after a failed RPC response and drive the sequence connect -> approve -> switch context -> execute so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/PlotNFT.ts` / `PlotNFT`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: stale PlotNFT wallet id during pool change; after a failed RPC response
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
