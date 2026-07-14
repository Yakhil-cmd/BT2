# Q556: pool-plotnft via UnconfirmedPlotNFT 556

## Question
Can an unprivileged attacker entering through the pool join/change flow in `UnconfirmedPlotNFT` (packages/api/src/@types/UnconfirmedPlotNFT.ts) control fee/reward amount near precision boundary with a cached permission entry and drive the sequence preview -> mutate controlled state -> confirm so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/UnconfirmedPlotNFT.ts` / `UnconfirmedPlotNFT`
- Entrypoint: pool join/change flow
- Attacker controls: fee/reward amount near precision boundary; with a cached permission entry
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
