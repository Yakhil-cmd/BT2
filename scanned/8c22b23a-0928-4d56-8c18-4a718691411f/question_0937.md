# Q937: walletconnect via handleOpenLink 937

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `handleOpenLink` (packages/gui/src/components/walletConnect/WalletConnectMetadata.tsx) control session metadata with misleading origin/icon/name fields with hidden Unicode characters and drive the sequence validate input -> normalize payload -> call RPC so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectMetadata.tsx` / `handleOpenLink`
- Entrypoint: pairing URI/import flow
- Attacker controls: session metadata with misleading origin/icon/name fields; with hidden Unicode characters
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
