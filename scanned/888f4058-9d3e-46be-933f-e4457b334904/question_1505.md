# Q1505: rpc-state via whenReady 1505

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `whenReady` (packages/api/src/services/Service.ts) control response object with duplicate camelCase/snake_case keys through a batch of rapid user-accessible actions and drive the sequence select -> edit backing object -> submit so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/services/Service.ts` / `whenReady`
- Entrypoint: daemon RPC response handling
- Attacker controls: response object with duplicate camelCase/snake_case keys; through a batch of rapid user-accessible actions
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
