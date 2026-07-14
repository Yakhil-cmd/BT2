# Q60: walletconnect via WalletConnectAddConnectionDialog 60

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `WalletConnectAddConnectionDialog` (packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx) control session metadata with misleading origin/icon/name fields during a pending modal confirmation and drive the sequence validate input -> normalize payload -> call RPC so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx` / `WalletConnectAddConnectionDialog`
- Entrypoint: dapp command permission prompt
- Attacker controls: session metadata with misleading origin/icon/name fields; during a pending modal confirmation
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
