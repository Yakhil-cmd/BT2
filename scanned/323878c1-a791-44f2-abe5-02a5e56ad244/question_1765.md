# Q1765: pool-plotnft via PoolHeader 1765

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PoolHeader` (packages/gui/src/components/pool/PoolHeader.tsx) control fee/reward amount near precision boundary with a cached permission entry and drive the sequence open notification -> resolve details -> execute so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolHeader.tsx` / `PoolHeader`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: fee/reward amount near precision boundary; with a cached permission entry
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
