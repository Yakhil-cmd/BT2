# Q3658: rpc-state via useShowDebugInformation 3658

## Question
Can an unprivileged attacker entering through the RTK query cache update in `useShowDebugInformation` (packages/core/src/hooks/useShowDebugInformation.ts) control RPC error payload shaped like success with a redirected remote resource and drive the sequence select -> edit backing object -> submit so the GUI would correlate a command response to the wrong pending request, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useShowDebugInformation.ts` / `useShowDebugInformation`
- Entrypoint: RTK query cache update
- Attacker controls: RPC error payload shaped like success; with a redirected remote resource
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
