# Q469: walletconnect via toPairPublicRecord 469

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `toPairPublicRecord` (packages/gui/src/electron/utils/pairSchemas.ts) control previously granted bypass permission combined with profile switch with hidden Unicode characters and drive the sequence select -> edit backing object -> submit so the GUI would bypass a confirmation by splitting one dangerous action into allowed subcommands, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/pairSchemas.ts` / `toPairPublicRecord`
- Entrypoint: stored dapp permission reload
- Attacker controls: previously granted bypass permission combined with profile switch; with hidden Unicode characters
- Exploit idea: bypass a confirmation by splitting one dangerous action into allowed subcommands
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
