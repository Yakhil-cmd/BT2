# Q3716: rpc-state via if 3716

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `if` (packages/gui/src/util/hasSensitiveContent.ts) control response object with duplicate camelCase/snake_case keys after a failed RPC response and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/hasSensitiveContent.ts` / `if`
- Entrypoint: camel/snake case transform path
- Attacker controls: response object with duplicate camelCase/snake_case keys; after a failed RPC response
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
