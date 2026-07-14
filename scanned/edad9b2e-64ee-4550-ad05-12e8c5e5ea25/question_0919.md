# Q919: rpc-state via lnFact 919

## Question
Can an unprivileged attacker entering through the RTK query cache update in `lnFact` (packages/gui/src/util/math.ts) control RPC error payload shaped like success with a stale Redux cache and drive the sequence validate input -> normalize payload -> call RPC so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/math.ts` / `lnFact`
- Entrypoint: RTK query cache update
- Attacker controls: RPC error payload shaped like success; with a stale Redux cache
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
