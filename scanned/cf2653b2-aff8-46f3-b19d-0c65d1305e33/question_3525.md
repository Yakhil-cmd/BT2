# Q3525: rpc-state via usePrefs 3525

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `usePrefs` (packages/api-react/src/hooks/usePrefs.ts) control RPC error payload shaped like success with hidden Unicode characters and drive the sequence download or render content -> trigger linked wallet action so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/hooks/usePrefs.ts` / `usePrefs`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; with hidden Unicode characters
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
