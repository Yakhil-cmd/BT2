# Q2291: pool-plotnft via handleDialogClose 2291

## Question
Can an unprivileged attacker entering through the farmer reward address management in `handleDialogClose` (packages/gui/src/components/plotNFT/PlotNFTGetPoolLoginLinkDialog.tsx) control pool URL/login response with mismatched launcher ID with a delayed metadata fetch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would absorb rewards with stale wallet/launcher state, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTGetPoolLoginLinkDialog.tsx` / `handleDialogClose`
- Entrypoint: farmer reward address management
- Attacker controls: pool URL/login response with mismatched launcher ID; with a delayed metadata fetch
- Exploit idea: absorb rewards with stale wallet/launcher state
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
