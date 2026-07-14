# Q831: pool-plotnft via PoolHeader 831

## Question
Can an unprivileged attacker entering through the payout instruction update in `PoolHeader` (packages/gui/src/components/pool/PoolHeader.tsx) control payout address with network or Unicode ambiguity with conflicting localStorage preferences and drive the sequence fetch -> cache -> refresh -> submit so the GUI would route pool login links through unsafe external URL handling, violating the invariant that absorb/join/change actions must not execute on stale selection, leading to Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval?

## Target
- File/function: `packages/gui/src/components/pool/PoolHeader.tsx` / `PoolHeader`
- Entrypoint: payout instruction update
- Attacker controls: payout address with network or Unicode ambiguity; with conflicting localStorage preferences
- Exploit idea: route pool login links through unsafe external URL handling
- Invariant to test: absorb/join/change actions must not execute on stale selection
- Expected Immunefi impact: Critical: unauthorized pooled farming reward claim or payout change; High: spoofed pool state causing wrong payout approval
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
