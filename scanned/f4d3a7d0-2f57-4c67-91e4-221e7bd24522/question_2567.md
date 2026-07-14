# Q2567: pool-plotnft via getPoolInfo 2567

## Question
Can an unprivileged attacker entering through the payout instruction update in `getPoolInfo` (packages/gui/src/util/getPoolInfo.ts) control payout address with network or Unicode ambiguity after a failed RPC response and drive the sequence load persisted state -> render approval -> execute command so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/util/getPoolInfo.ts` / `getPoolInfo`
- Entrypoint: payout instruction update
- Attacker controls: payout address with network or Unicode ambiguity; after a failed RPC response
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
