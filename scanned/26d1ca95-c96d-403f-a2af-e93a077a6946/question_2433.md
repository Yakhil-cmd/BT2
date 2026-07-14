# Q2433: pool-plotnft via PlotNFTState 2433

## Question
Can an unprivileged attacker entering through the farmer reward address management in `PlotNFTState` (packages/api/src/constants/PlotNFTState.ts) control stale PlotNFT wallet id during pool change with precision-boundary values and drive the sequence download or render content -> trigger linked wallet action so the GUI would route pool login links through unsafe external URL handling, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/constants/PlotNFTState.ts` / `PlotNFTState`
- Entrypoint: farmer reward address management
- Attacker controls: stale PlotNFT wallet id during pool change; with precision-boundary values
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
