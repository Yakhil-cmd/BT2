# Q699: pool-plotnft via getPoolInfo 699

## Question
Can an unprivileged attacker entering through the farmer reward address management in `getPoolInfo` (packages/gui/src/util/getPoolInfo.ts) control fee/reward amount near precision boundary during a pending modal confirmation and drive the sequence select -> edit backing object -> submit so the GUI would submit payout or pool change for a different PlotNFT than the user selected, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/util/getPoolInfo.ts` / `getPoolInfo`
- Entrypoint: farmer reward address management
- Attacker controls: fee/reward amount near precision boundary; during a pending modal confirmation
- Exploit idea: submit payout or pool change for a different PlotNFT than the user selected
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
