# Q635: rpc-state via getChecksum 635

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `getChecksum` (packages/gui/src/electron/utils/getChecksum.ts) control RPC error payload shaped like success with precision-boundary values and drive the sequence download or render content -> trigger linked wallet action so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/getChecksum.ts` / `getChecksum`
- Entrypoint: daemon RPC response handling
- Attacker controls: RPC error payload shaped like success; with precision-boundary values
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
