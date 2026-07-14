# Q3877: pool-plotnft via PlotNFTExternal 3877

## Question
Can an unprivileged attacker entering through the pool login link action in `PlotNFTExternal` (packages/api/src/@types/PlotNFTExternal.ts) control stale PlotNFT wallet id during pool change with conflicting localStorage preferences and drive the sequence fetch -> cache -> refresh -> submit so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/PlotNFTExternal.ts` / `PlotNFTExternal`
- Entrypoint: pool login link action
- Attacker controls: stale PlotNFT wallet id during pool change; with conflicting localStorage preferences
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
