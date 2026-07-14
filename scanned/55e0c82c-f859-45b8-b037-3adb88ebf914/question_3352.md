# Q3352: pool-plotnft via PlotNFT 3352

## Question
Can an unprivileged attacker entering through the pool join/change flow in `PlotNFT` (packages/api/src/@types/PlotNFT.ts) control external pool metadata changing between preview and submit after a network switch and drive the sequence select -> edit backing object -> submit so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/PlotNFT.ts` / `PlotNFT`
- Entrypoint: pool join/change flow
- Attacker controls: external pool metadata changing between preview and submit; after a network switch
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
