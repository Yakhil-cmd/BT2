# Q2717: rpc-state via useLocale 2717

## Question
Can an unprivileged attacker entering through the RTK query cache update in `useLocale` (packages/core/src/hooks/useLocale.ts) control large numeric fields near JS precision limits with conflicting localStorage preferences and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useLocale.ts` / `useLocale`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; with conflicting localStorage preferences
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
