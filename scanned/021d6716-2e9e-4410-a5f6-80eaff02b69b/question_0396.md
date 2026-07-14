# Q396: rpc-state via WalletCATSelect 396

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `WalletCATSelect` (packages/wallets/src/components/cat/WalletCATSelect.tsx) control out-of-order event and query responses with conflicting localStorage preferences and drive the sequence open notification -> resolve details -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/cat/WalletCATSelect.tsx` / `WalletCATSelect`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; with conflicting localStorage preferences
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
