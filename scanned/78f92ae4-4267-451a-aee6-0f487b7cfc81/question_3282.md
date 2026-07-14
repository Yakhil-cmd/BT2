# Q3282: walletconnect via setCommands 3282

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `setCommands` (packages/gui/src/hooks/useBypassCommands.ts) control previously granted bypass permission combined with profile switch with a delayed metadata fetch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useBypassCommands.ts` / `setCommands`
- Entrypoint: stored dapp permission reload
- Attacker controls: previously granted bypass permission combined with profile switch; with a delayed metadata fetch
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
