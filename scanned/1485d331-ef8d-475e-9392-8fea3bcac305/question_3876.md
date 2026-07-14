# Q3876: pool-plotnft via PlotNFTExternal 3876

## Question
Can an unprivileged attacker entering through the payout instruction update in `PlotNFTExternal` (packages/api/src/@types/PlotNFTExternal.ts) control payout address with network or Unicode ambiguity with conflicting localStorage preferences and drive the sequence fetch -> cache -> refresh -> submit so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/PlotNFTExternal.ts` / `PlotNFTExternal`
- Entrypoint: payout instruction update
- Attacker controls: payout address with network or Unicode ambiguity; with conflicting localStorage preferences
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
