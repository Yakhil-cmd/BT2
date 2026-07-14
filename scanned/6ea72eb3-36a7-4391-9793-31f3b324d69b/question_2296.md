# Q2296: rpc-state via WalletType 2296

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `WalletType` (packages/gui/src/electron/constants/WalletType.ts) control response object with duplicate camelCase/snake_case keys after a profile switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/constants/WalletType.ts` / `WalletType`
- Entrypoint: camel/snake case transform path
- Attacker controls: response object with duplicate camelCase/snake_case keys; after a profile switch
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
