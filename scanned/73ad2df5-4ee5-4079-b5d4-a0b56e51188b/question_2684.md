# Q2684: rpc-state via toSnakeCase 2684

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `toSnakeCase` (packages/api/src/utils/toSnakeCase.ts) control response object with duplicate camelCase/snake_case keys with hidden Unicode characters and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/utils/toSnakeCase.ts` / `toSnakeCase`
- Entrypoint: daemon RPC response handling
- Attacker controls: response object with duplicate camelCase/snake_case keys; with hidden Unicode characters
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
