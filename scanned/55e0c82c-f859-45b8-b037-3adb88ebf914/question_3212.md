# Q3212: rpc-state via StandardWallet 3212

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `StandardWallet` (packages/wallets/src/components/standard/WalletStandard.tsx) control large numeric fields near JS precision limits with a redirected remote resource and drive the sequence import -> parse -> preview -> submit so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/standard/WalletStandard.tsx` / `StandardWallet`
- Entrypoint: daemon RPC response handling
- Attacker controls: large numeric fields near JS precision limits; with a redirected remote resource
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
