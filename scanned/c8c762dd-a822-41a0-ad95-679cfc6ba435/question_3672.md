# Q3672: pool-plotnft via if 3672

## Question
Can an unprivileged attacker entering through the PlotNFT absorb rewards action in `if` (packages/gui/src/components/plotNFT/PlotNFTAbsorbRewards.tsx) control pool URL/login response with mismatched launcher ID with case-normalized identifiers and drive the sequence select -> edit backing object -> submit so the GUI would normalize payout addresses differently between validation and RPC payload, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTAbsorbRewards.tsx` / `if`
- Entrypoint: PlotNFT absorb rewards action
- Attacker controls: pool URL/login response with mismatched launcher ID; with case-normalized identifiers
- Exploit idea: normalize payout addresses differently between validation and RPC payload
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
