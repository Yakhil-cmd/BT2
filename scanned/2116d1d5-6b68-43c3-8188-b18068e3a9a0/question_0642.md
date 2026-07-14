# Q642: rpc-state via generateScriptContent 642

## Question
Can an unprivileged attacker entering through the RTK query cache update in `generateScriptContent` (packages/gui/src/electron/utils/openReactDialog.tsx) control large numeric fields near JS precision limits after a failed RPC response and drive the sequence preview -> mutate controlled state -> confirm so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/openReactDialog.tsx` / `generateScriptContent`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; after a failed RPC response
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
