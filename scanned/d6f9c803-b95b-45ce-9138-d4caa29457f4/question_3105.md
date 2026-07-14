# Q3105: walletconnect via for 3105

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `for` (packages/gui/src/electron/commands/filterRequestedDappCommands.ts) control chainId/account/fingerprint mismatch after canceling and reopening the dialog and drive the sequence import -> parse -> preview -> submit so the GUI would route a dapp request to a wallet or fingerprint not approved for that session, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/filterRequestedDappCommands.ts` / `for`
- Entrypoint: stored dapp permission reload
- Attacker controls: chainId/account/fingerprint mismatch; after canceling and reopening the dialog
- Exploit idea: route a dapp request to a wallet or fingerprint not approved for that session
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
