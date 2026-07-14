# Q661: rpc-state via useIsServiceRunning 661

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `useIsServiceRunning` (packages/gui/src/hooks/useIsServiceRunning.ts) control large numeric fields near JS precision limits with case-normalized identifiers and drive the sequence download or render content -> trigger linked wallet action so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/hooks/useIsServiceRunning.ts` / `useIsServiceRunning`
- Entrypoint: daemon RPC response handling
- Attacker controls: large numeric fields near JS precision limits; with case-normalized identifiers
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
