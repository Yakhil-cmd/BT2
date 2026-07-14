# Q401: rpc-state via WalletCATTAILDialog 401

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `WalletCATTAILDialog` (packages/wallets/src/components/cat/WalletCATTAILDialog.tsx) control RPC error payload shaped like success with a cached permission entry and drive the sequence download or render content -> trigger linked wallet action so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/cat/WalletCATTAILDialog.tsx` / `WalletCATTAILDialog`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; with a cached permission entry
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
