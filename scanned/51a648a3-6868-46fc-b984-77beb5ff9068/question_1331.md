# Q1331: rpc-state via handleCreateNew 1331

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `handleCreateNew` (packages/wallets/src/components/cat/WalletCATSelect.tsx) control subscription event for a different wallet/fingerprint with a cached permission entry and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/cat/WalletCATSelect.tsx` / `handleCreateNew`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; with a cached permission entry
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
