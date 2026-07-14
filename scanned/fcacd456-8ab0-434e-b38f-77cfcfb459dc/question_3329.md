# Q3329: rpc-state via ServiceOld 3329

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `ServiceOld` (packages/api-react/src/@types/ServiceOld.ts) control large numeric fields near JS precision limits with case-normalized identifiers and drive the sequence validate input -> normalize payload -> call RPC so the GUI would display one balance/asset state while executing with another, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/@types/ServiceOld.ts` / `ServiceOld`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with case-normalized identifiers
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
