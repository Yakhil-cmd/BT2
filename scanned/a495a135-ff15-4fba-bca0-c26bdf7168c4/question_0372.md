# Q372: rpc-state via StyledRoot 372

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `StyledRoot` (packages/wallets/src/components/WalletsSidebar.tsx) control subscription event for a different wallet/fingerprint during a pending modal confirmation and drive the sequence load persisted state -> render approval -> execute command so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletsSidebar.tsx` / `StyledRoot`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; during a pending modal confirmation
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
