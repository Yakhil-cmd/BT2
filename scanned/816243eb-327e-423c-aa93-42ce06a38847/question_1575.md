# Q1575: rpc-state via manageDaemonLifetime 1575

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `manageDaemonLifetime` (packages/gui/src/electron/utils/manageDaemonLifetime.ts) control large numeric fields near JS precision limits with a duplicate identifier and drive the sequence import -> parse -> preview -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/manageDaemonLifetime.ts` / `manageDaemonLifetime`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; with a duplicate identifier
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
