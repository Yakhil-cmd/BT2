# Q2665: rpc-state via index 2665

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `index` (packages/api/src/constants/index.ts) control subscription event for a different wallet/fingerprint with a delayed metadata fetch and drive the sequence download or render content -> trigger linked wallet action so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/constants/index.ts` / `index`
- Entrypoint: camel/snake case transform path
- Attacker controls: subscription event for a different wallet/fingerprint; with a delayed metadata fetch
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
