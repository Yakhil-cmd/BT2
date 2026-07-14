# Q1595: rpc-state via isRunning 1595

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `isRunning` (packages/gui/src/hooks/useIsServiceRunning.ts) control response object with duplicate camelCase/snake_case keys after a failed RPC response and drive the sequence import -> parse -> preview -> submit so the GUI would display one balance/asset state while executing with another, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/hooks/useIsServiceRunning.ts` / `isRunning`
- Entrypoint: camel/snake case transform path
- Attacker controls: response object with duplicate camelCase/snake_case keys; after a failed RPC response
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
