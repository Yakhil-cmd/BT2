# Q319: walletconnect via isDappAllowedCommand 319

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `isDappAllowedCommand` (packages/gui/src/electron/commands/isDappAllowedCommand.ts) control session metadata with misleading origin/icon/name fields with a duplicate identifier and drive the sequence select -> edit backing object -> submit so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isDappAllowedCommand.ts` / `isDappAllowedCommand`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: session metadata with misleading origin/icon/name fields; with a duplicate identifier
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
