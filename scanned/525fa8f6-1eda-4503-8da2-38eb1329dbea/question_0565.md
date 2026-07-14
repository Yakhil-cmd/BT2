# Q565: pool-plotnft via PlotNFTState 565

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `PlotNFTState` (packages/api/src/constants/PlotNFTState.ts) control pool URL/login response with mismatched launcher ID after a failed RPC response and drive the sequence open notification -> resolve details -> execute so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/constants/PlotNFTState.ts` / `PlotNFTState`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: pool URL/login response with mismatched launcher ID; after a failed RPC response
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
