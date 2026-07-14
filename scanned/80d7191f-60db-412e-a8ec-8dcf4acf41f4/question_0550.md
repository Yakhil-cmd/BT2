# Q550: pool-plotnft via PlotNFT 550

## Question
Can an unprivileged attacker entering through the pool login link action in `PlotNFT` (packages/api/src/@types/PlotNFT.ts) control pool URL/login response with mismatched launcher ID during a pending modal confirmation and drive the sequence download or render content -> trigger linked wallet action so the GUI would route pool login links through unsafe external URL handling, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/api/src/@types/PlotNFT.ts` / `PlotNFT`
- Entrypoint: pool login link action
- Attacker controls: pool URL/login response with mismatched launcher ID; during a pending modal confirmation
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
