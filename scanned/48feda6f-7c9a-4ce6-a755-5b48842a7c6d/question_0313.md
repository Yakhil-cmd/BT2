# Q313: walletconnect via humanizeDappCommandName 313

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `humanizeDappCommandName` (packages/gui/src/electron/commands/humanizeDappCommandName.ts) control chainId/account/fingerprint mismatch with case-normalized identifiers and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/humanizeDappCommandName.ts` / `humanizeDappCommandName`
- Entrypoint: pairing URI/import flow
- Attacker controls: chainId/account/fingerprint mismatch; with case-normalized identifiers
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
