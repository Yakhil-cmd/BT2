# Q1583: rpc-state via if 1583

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `if` (packages/gui/src/electron/utils/untildify.ts) control large numeric fields near JS precision limits after canceling and reopening the dialog and drive the sequence fetch -> cache -> refresh -> submit so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/untildify.ts` / `if`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; after canceling and reopening the dialog
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
