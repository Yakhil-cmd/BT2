# Q1434: walletconnect via setEnabled 1434

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `setEnabled` (packages/gui/src/hooks/useWalletConnectPreferences.ts) control chainId/account/fingerprint mismatch with precision-boundary values and drive the sequence preview -> mutate controlled state -> confirm so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useWalletConnectPreferences.ts` / `setEnabled`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: chainId/account/fingerprint mismatch; with precision-boundary values
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
