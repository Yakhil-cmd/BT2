# Q2290: pool-plotnft via handleDialogClose 2290

## Question
Can an unprivileged attacker entering through the pool login link action in `handleDialogClose` (packages/gui/src/components/plotNFT/PlotNFTGetPoolLoginLinkDialog.tsx) control pool URL/login response with mismatched launcher ID with a delayed metadata fetch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTGetPoolLoginLinkDialog.tsx` / `handleDialogClose`
- Entrypoint: pool login link action
- Attacker controls: pool URL/login response with mismatched launcher ID; with a delayed metadata fetch
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
