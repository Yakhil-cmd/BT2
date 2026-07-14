# Q1788: rpc-state via setAutoHide 1788

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `setAutoHide` (packages/core/src/hooks/useScrollbarsSettings.tsx) control out-of-order event and query responses during a pending modal confirmation and drive the sequence load persisted state -> render approval -> execute command so the GUI would correlate a command response to the wrong pending request, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useScrollbarsSettings.tsx` / `setAutoHide`
- Entrypoint: WebSocket event subscription
- Attacker controls: out-of-order event and query responses; during a pending modal confirmation
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
