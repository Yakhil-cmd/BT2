# Q1949: walletconnect via getDappCommandMetadata 1949

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `getDappCommandMetadata` (packages/gui/src/electron/commands/getDappCommandMetadata.ts) control session metadata with misleading origin/icon/name fields after a failed RPC response and drive the sequence import -> parse -> preview -> submit so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/getDappCommandMetadata.ts` / `getDappCommandMetadata`
- Entrypoint: pairing URI/import flow
- Attacker controls: session metadata with misleading origin/icon/name fields; after a failed RPC response
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
