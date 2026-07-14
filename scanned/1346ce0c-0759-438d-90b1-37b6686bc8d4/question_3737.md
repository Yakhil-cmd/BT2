# Q3737: walletconnect via WalletConnectMetadata 3737

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `WalletConnectMetadata` (packages/gui/src/components/walletConnect/WalletConnectMetadata.tsx) control session metadata with misleading origin/icon/name fields with a duplicate identifier and drive the sequence load persisted state -> render approval -> execute command so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectMetadata.tsx` / `WalletConnectMetadata`
- Entrypoint: pairing URI/import flow
- Attacker controls: session metadata with misleading origin/icon/name fields; with a duplicate identifier
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
