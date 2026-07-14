# Q1016: walletconnect via isSignCommand 1016

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `isSignCommand` (packages/gui/src/electron/commands/isSignCommand.ts) control session metadata with misleading origin/icon/name fields with a cached permission entry and drive the sequence import -> parse -> preview -> submit so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isSignCommand.ts` / `isSignCommand`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: session metadata with misleading origin/icon/name fields; with a cached permission entry
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
