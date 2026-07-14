# Q683: pool-plotnft via usePoolInfo 683

## Question
Can an unprivileged attacker entering through the farmer reward address management in `usePoolInfo` (packages/gui/src/hooks/usePoolInfo.ts) control fee/reward amount near precision boundary during a pending modal confirmation and drive the sequence fetch -> cache -> refresh -> submit so the GUI would route pool login links through unsafe external URL handling, violating the invariant that PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/hooks/usePoolInfo.ts` / `usePoolInfo`
- Entrypoint: farmer reward address management
- Attacker controls: fee/reward amount near precision boundary; during a pending modal confirmation
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: PlotNFT launcher, walletId, pool URL, payout address, fee, and reward action must remain bound and network-correct through RPC submission
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
