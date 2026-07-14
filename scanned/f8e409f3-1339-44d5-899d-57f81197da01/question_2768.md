# Q2768: pool-plotnft via useFarmerStatus 2768

## Question
Can an unprivileged attacker entering through the pool login link action in `useFarmerStatus` (packages/gui/src/hooks/useFarmerStatus.ts) control stale PlotNFT wallet id during pool change with reordered RPC events and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/useFarmerStatus.ts` / `useFarmerStatus`
- Entrypoint: pool login link action
- Attacker controls: stale PlotNFT wallet id during pool change; with reordered RPC events
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
