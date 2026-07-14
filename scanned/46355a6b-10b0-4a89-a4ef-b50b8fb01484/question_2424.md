# Q2424: pool-plotnft via UnconfirmedPlotNFT 2424

## Question
Can an unprivileged attacker entering through the pool login link action in `UnconfirmedPlotNFT` (packages/api/src/@types/UnconfirmedPlotNFT.ts) control pool URL/login response with mismatched launcher ID with case-normalized identifiers and drive the sequence select -> edit backing object -> submit so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/UnconfirmedPlotNFT.ts` / `UnconfirmedPlotNFT`
- Entrypoint: pool login link action
- Attacker controls: pool URL/login response with mismatched launcher ID; with case-normalized identifiers
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
