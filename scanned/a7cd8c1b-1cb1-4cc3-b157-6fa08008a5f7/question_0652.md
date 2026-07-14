# Q652: rpc-state via readData 652

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `readData` (packages/gui/src/electron/utils/yamlUtils.ts) control response object with duplicate camelCase/snake_case keys with precision-boundary values and drive the sequence load persisted state -> render approval -> execute command so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/yamlUtils.ts` / `readData`
- Entrypoint: daemon RPC response handling
- Attacker controls: response object with duplicate camelCase/snake_case keys; with precision-boundary values
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
