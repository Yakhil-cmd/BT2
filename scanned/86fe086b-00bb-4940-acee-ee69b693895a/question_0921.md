# Q921: rpc-state via removeHexPrefix 921

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `removeHexPrefix` (packages/gui/src/util/removeHexPrefix.ts) control out-of-order event and query responses after canceling and reopening the dialog and drive the sequence open notification -> resolve details -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/removeHexPrefix.ts` / `removeHexPrefix`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; after canceling and reopening the dialog
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
