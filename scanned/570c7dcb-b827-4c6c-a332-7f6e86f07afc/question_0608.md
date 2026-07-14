# Q608: pool-plotnft via PlotNFTExternalState 608

## Question
Can an unprivileged attacker entering through the payout instruction update in `PlotNFTExternalState` (packages/gui/src/components/plotNFT/PlotNFTExternalState.tsx) control stale PlotNFT wallet id during pool change during a pending modal confirmation and drive the sequence validate input -> normalize payload -> call RPC so the GUI would accept pool metadata that displays one payout target while submitting another, violating the invariant that external pool data must not override confirmed payout state, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/plotNFT/PlotNFTExternalState.tsx` / `PlotNFTExternalState`
- Entrypoint: payout instruction update
- Attacker controls: stale PlotNFT wallet id during pool change; during a pending modal confirmation
- Exploit idea: accept pool metadata that displays one payout target while submitting another
- Invariant to test: external pool data must not override confirmed payout state
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
