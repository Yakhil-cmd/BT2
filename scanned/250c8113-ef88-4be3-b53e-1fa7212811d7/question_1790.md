# Q1790: rpc-state via useShowDebugInformation 1790

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `useShowDebugInformation` (packages/core/src/hooks/useShowDebugInformation.ts) control large numeric fields near JS precision limits with reordered RPC events and drive the sequence preview -> mutate controlled state -> confirm so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useShowDebugInformation.ts` / `useShowDebugInformation`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; with reordered RPC events
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
