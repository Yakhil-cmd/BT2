# Q897: rpc-state via useAssetIdName 897

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `useAssetIdName` (packages/gui/src/hooks/useAssetIdName.ts) control RPC error payload shaped like success with case-normalized identifiers and drive the sequence connect -> approve -> switch context -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/hooks/useAssetIdName.ts` / `useAssetIdName`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; with case-normalized identifiers
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
