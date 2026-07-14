# Q456: rpc-state via mojoToCATLocaleString 456

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `mojoToCATLocaleString` (packages/gui/src/electron/utils/mojoToCATLocaleString.ts) control RPC error payload shaped like success after a profile switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/mojoToCATLocaleString.ts` / `mojoToCATLocaleString`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; after a profile switch
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
