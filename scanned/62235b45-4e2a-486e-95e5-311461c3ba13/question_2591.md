# Q2591: rpc-state via isEqual 2591

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `isEqual` (packages/api-react/src/hooks/usePrefs.ts) control response object with duplicate camelCase/snake_case keys during a pending modal confirmation and drive the sequence validate input -> normalize payload -> call RPC so the GUI would display one balance/asset state while executing with another, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/hooks/usePrefs.ts` / `isEqual`
- Entrypoint: daemon RPC response handling
- Attacker controls: response object with duplicate camelCase/snake_case keys; during a pending modal confirmation
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
