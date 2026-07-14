# Q414: rpc-state via index 414

## Question
Can an unprivileged attacker entering through the service command response correlation in `index` (packages/wallets/src/hooks/index.ts) control RPC error payload shaped like success with hidden Unicode characters and drive the sequence validate input -> normalize payload -> call RPC so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/hooks/index.ts` / `index`
- Entrypoint: service command response correlation
- Attacker controls: RPC error payload shaped like success; with hidden Unicode characters
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
