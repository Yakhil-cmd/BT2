# Q3679: pool-plotnft via urls 3679

## Question
Can an unprivileged attacker entering through the payout instruction update in `urls` (packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx) control pool URL/login response with mismatched launcher ID with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx` / `urls`
- Entrypoint: payout instruction update
- Attacker controls: pool URL/login response with mismatched launcher ID; with a redirected remote resource
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
