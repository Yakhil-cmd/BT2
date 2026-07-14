# Q2185: walletconnect via isBalanceCommand 2185

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `isBalanceCommand` (packages/gui/src/electron/commands/isBalanceCommand.ts) control previously granted bypass permission combined with profile switch through a batch of rapid user-accessible actions and drive the sequence select -> edit backing object -> submit so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/isBalanceCommand.ts` / `isBalanceCommand`
- Entrypoint: pairing URI/import flow
- Attacker controls: previously granted bypass permission combined with profile switch; through a batch of rapid user-accessible actions
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
