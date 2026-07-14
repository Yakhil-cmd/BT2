# Q3409: pool-plotnft via if 3409

## Question
Can an unprivileged attacker entering through the pool join/change flow in `if` (packages/gui/src/components/plotNFT/PlotNFTChangePool.tsx) control fee/reward amount near precision boundary with a redirected remote resource and drive the sequence select -> edit backing object -> submit so the GUI would route pool login links through unsafe external URL handling, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTChangePool.tsx` / `if`
- Entrypoint: pool join/change flow
- Attacker controls: fee/reward amount near precision boundary; with a redirected remote resource
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
