# Q1696: pool-plotnft via HarvesterPlotsPaginated 1696

## Question
Can an unprivileged attacker entering through the pool join/change flow in `HarvesterPlotsPaginated` (packages/api/src/@types/HarvesterPlotsPaginated.ts) control fee/reward amount near precision boundary through a batch of rapid user-accessible actions and drive the sequence fetch -> cache -> refresh -> submit so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/HarvesterPlotsPaginated.ts` / `HarvesterPlotsPaginated`
- Entrypoint: pool join/change flow
- Attacker controls: fee/reward amount near precision boundary; through a batch of rapid user-accessible actions
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
